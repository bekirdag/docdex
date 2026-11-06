#!/usr/bin/env python3
"""Experimental AST-chunk retrieval through Docdex, with a separate bounded code index."""
import argparse
import hashlib
import fcntl
import json
import math
import sqlite3
import struct
import time
import urllib.parse
import urllib.request
from pathlib import Path
from c2llm_service import MODEL, REVISION, DIMENSIONS, MAX_TOKENS

MAX_CHUNKS = 1024  # <= 3.5 MiB of float32 vectors; no unbounded full-vector scan.
FINGERPRINT = f'{MODEL}@{REVISION}:pma:normalized:{DIMENSIONS}:{MAX_TOKENS}:chunks-v1'


def request(url, payload=None, timeout=60):
    req = urllib.request.Request(url, data=None if payload is None else json.dumps(payload).encode(),
        headers={'Content-Type': 'application/json'})
    with urllib.request.urlopen(req, timeout=timeout) as response:
        return json.load(response)


def tool(base, repo, name, args):
    response = request(base + '/v1/mcp', {'jsonrpc': '2.0', 'id': 1, 'method': 'tools/call',
        'params': {'name': name, 'arguments': {'project_root': str(repo), **args}}})
    if 'error' in response:
        raise RuntimeError(response['error'])
    result = response.get('result', response)
    if result.get('isError'):
        raise RuntimeError(result)
    return json.loads(next(item['text'] for item in result['content'] if item['type'] == 'text'))


def embed(base, text):
    endpoint = urllib.parse.urlparse(base)
    if endpoint.scheme != 'http' or endpoint.hostname not in ('127.0.0.1', 'localhost', '::1'):
        raise ValueError('experimental code embeddings require a loopback HTTP service')
    response = request(base.rstrip('/') + '/v1/embeddings', {'model': MODEL, 'input': text})
    vector = response['data'][0]['embedding']
    if len(vector) != DIMENSIONS or not all(math.isfinite(v) for v in vector):
        raise ValueError('embedding model/dimension mismatch')
    return vector


def reciprocal_rank_fusion(rankings, limit=8):
    scores = {}
    for ranking in rankings:
        seen = set()
        for rank, path in enumerate(ranking, 1):
            if path not in seen:
                scores[path] = scores.get(path, 0.0) + 1.0 / (60 + rank)
                seen.add(path)
    return sorted(scores.items(), key=lambda item: (-item[1], item[0]))[:limit]


def chunks(base, repo, paths):
    for path in sorted(set(paths)):
        definitions = tool(base, repo, 'docdex_symbols', {'path': path})
        source = tool(base, repo, 'docdex_open', {'path': path, 'head': 10000})['content']
        lines = source.splitlines()
        selected = [s for s in definitions.get('symbols', [])
                    if s.get('kind') in ('function', 'method', 'class', 'struct', 'interface')]
        for symbol in selected:
            span = symbol['range']; start = span['start_line']; end = span['end_line']
            if not 1 <= start <= end <= len(lines):
                continue
            # Large definitions are split into bounded, overlapping windows.
            for offset in range(start - 1, end, 60):
                stop = min(offset + 80, end)
                text = f'{path}\n{symbol["name"]}\n' + '\n'.join(lines[offset:stop])
                yield {'path': path, 'name': symbol['name'], 'start': offset + 1,
                       'end': stop, 'text': text[:16000]}
                if stop == end:
                    break


def connect(path):
    conn = sqlite3.connect(path)
    conn.execute('CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT NOT NULL)')
    conn.execute('CREATE TABLE IF NOT EXISTS chunks (id TEXT PRIMARY KEY, path TEXT, name TEXT, start INT, end INT, content_hash TEXT, vector BLOB)')
    return conn


def build(args, repo_id):
    args.index.parent.mkdir(parents=True, exist_ok=True)
    with args.index.with_suffix(args.index.suffix + '.lock').open('a') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        return build_locked(args, repo_id)


def file_stamp(path):
    try:
        stat = path.stat()
        return [stat.st_size, stat.st_mtime_ns, stat.st_ino]
    except OSError:
        return None


def build_locked(args, repo_id):
    stamps = {path: file_stamp(args.repo / path) for path in args.paths}
    conn = connect(args.index)
    old = dict(conn.execute('SELECT key,value FROM meta'))
    if old and (old.get('repo_id') != repo_id or old.get('fingerprint') != FINGERPRINT):
        raise ValueError('index belongs to another repository/model; choose a new index file')
    reused = encoded = 0
    # Network work happens before a single atomic replacement transaction.
    rows = []
    truncated = False
    for chunk in chunks(args.docdex_url, args.repo, args.paths):
        if len(rows) >= MAX_CHUNKS:
            truncated = True
            break
        content_hash = hashlib.sha256((FINGERPRINT + chunk['text']).encode()).hexdigest()
        cached = conn.execute('SELECT vector FROM chunks WHERE content_hash=? LIMIT 1', (content_hash,)).fetchone()
        if cached:
            vector = cached[0]; reused += 1
        else:
            vector = struct.pack(f'<{DIMENSIONS}f', *embed(args.embedding_url, chunk['text'])); encoded += 1
        key = f'{chunk["path"]}:{chunk["start"]}:{chunk["end"]}:{chunk["name"]}'
        rows.append((key, chunk['path'], chunk['name'], chunk['start'], chunk['end'], content_hash, vector))
    with conn:
        conn.execute('DELETE FROM chunks')
        conn.executemany('INSERT INTO chunks VALUES (?,?,?,?,?,?,?)', rows)
        conn.executemany('INSERT OR REPLACE INTO meta VALUES (?,?)', [
            ('repo_id', repo_id), ('fingerprint', FINGERPRINT), ('repo_root', str(args.repo)),
            ('paths', json.dumps(sorted(set(args.paths)))), ('truncated', str(truncated)),
            ('file_stamps', json.dumps(stamps)),
            ('created_at', str(time.time()))])
    return {'chunks': len(rows), 'encoded': encoded, 'reused': reused,
            'coverage_truncated': truncated, 'max_chunks': MAX_CHUNKS, 'fingerprint': FINGERPRINT}


def search(args, repo_id):
    # Read-only open: a search never creates or rebuilds a vector index.
    conn = sqlite3.connect(args.index.resolve().as_uri() + '?mode=ro', uri=True)
    metadata = dict(conn.execute('SELECT key,value FROM meta'))
    if metadata.get('repo_id') != repo_id or metadata.get('fingerprint') != FINGERPRINT:
        raise ValueError('index belongs to another repository/model; rebuild separately')
    query = embed(args.embedding_url, args.query)
    ranked = []
    stamps = json.loads(metadata.get('file_stamps', '{}'))
    stale = {path for path, stamp in stamps.items() if file_stamp(args.repo / path) != stamp}
    for path, name, start, end, blob in conn.execute('SELECT path,name,start,end,vector FROM chunks LIMIT ?', (MAX_CHUNKS,)):
        # Exclude deleted files; refresh the explicit code index after edits.
        if path in stale or path not in stamps or not (args.repo / path).is_file():
            continue
        vector = struct.unpack(f'<{DIMENSIONS}f', blob)
        score = sum(a*b for a,b in zip(query, vector))
        ranked.append({'path': path, 'name': name, 'start_line': start, 'end_line': end, 'cosine': score})
    ranked.sort(key=lambda item: (-item['cosine'], item['path'], item['start_line']))
    lexical = request(args.docdex_url + '/search?' + urllib.parse.urlencode({
        'repo_id': repo_id, 'q': args.query, 'limit': 8, 'force_web': 'false'}))
    lexical_paths = [hit.get('rel_path', hit.get('path')) for hit in lexical.get('hits', [])]
    return {'hybrid': reciprocal_rank_fusion([lexical_paths, [item['path'] for item in ranked[:32]]]),
            'semantic_chunks': ranked[:8], 'lexical_paths': lexical_paths,
            'index': metadata, 'stale_files': sorted(stale), 'experimental': True}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('command', choices=['index', 'search'])
    parser.add_argument('--repo', type=Path, required=True)
    parser.add_argument('--index', type=Path, required=True)
    parser.add_argument('--docdex-url', default='http://127.0.0.1:28491')
    parser.add_argument('--embedding-url', default='http://127.0.0.1:28521')
    parser.add_argument('--paths', nargs='*', default=[])
    parser.add_argument('--query')
    args = parser.parse_args(); args.repo = args.repo.resolve()
    if args.command == 'index' and not args.paths:
        parser.error('index requires an explicit --paths corpus')
    if args.command == 'search' and not args.query:
        parser.error('search requires --query')
    mounted = request(args.docdex_url + '/v1/initialize', {'rootUri': args.repo.as_uri()})
    print(json.dumps((build if args.command == 'index' else search)(args, mounted['repo_id']), indent=2))
