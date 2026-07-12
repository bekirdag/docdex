#!/usr/bin/env python3
"""Create a byte-reproducible single-binary tar.gz release archive."""

from __future__ import annotations

import argparse
import gzip
import hashlib
import io
import os
from pathlib import Path
import tarfile
import tempfile


def parse_source_date_epoch(raw: str) -> int:
    value = raw.strip()
    if not value.isdecimal():
        raise ValueError("source date epoch must be a non-negative integer")
    epoch = int(value)
    if epoch > 253402300799:
        raise ValueError("source date epoch is outside the supported timestamp range")
    return epoch


def create_archive(
    *, input_path: Path, archive_name: str, output_path: Path, source_date_epoch: int
) -> str:
    if not input_path.is_file():
        raise ValueError(f"release binary does not exist: {input_path}")
    if not archive_name or Path(archive_name).name != archive_name:
        raise ValueError("archive name must be a single non-empty filename")

    payload = input_path.read_bytes()
    tar_buffer = io.BytesIO()
    with tarfile.open(fileobj=tar_buffer, mode="w", format=tarfile.GNU_FORMAT) as archive:
        member = tarfile.TarInfo(archive_name)
        member.size = len(payload)
        member.mode = 0o755
        member.mtime = source_date_epoch
        member.uid = 0
        member.gid = 0
        member.uname = ""
        member.gname = ""
        archive.addfile(member, io.BytesIO(payload))

    output_path.parent.mkdir(parents=True, exist_ok=True)
    file_descriptor, temp_name = tempfile.mkstemp(dir=output_path.parent)
    os.close(file_descriptor)
    temp_path = Path(temp_name)
    try:
        with temp_path.open("wb") as raw_temp:
            with gzip.GzipFile(
                filename="",
                mode="wb",
                compresslevel=9,
                fileobj=raw_temp,
                mtime=source_date_epoch,
            ) as compressed:
                compressed.write(tar_buffer.getvalue())
            raw_temp.flush()
            os.fsync(raw_temp.fileno())
        os.replace(temp_path, output_path)
    except BaseException:
        temp_path.unlink(missing_ok=True)
        raise

    digest = hashlib.sha256(output_path.read_bytes()).hexdigest()
    checksum_path = output_path.with_name(f"{output_path.name}.sha256")
    checksum_path.write_text(f"{digest}  {output_path.name}\n", encoding="utf-8")
    return digest


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", required=True, type=Path)
    parser.add_argument("--archive-name", required=True)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument(
        "--source-date-epoch",
        default=os.environ.get("SOURCE_DATE_EPOCH"),
        help="Unix epoch from the immutable source commit (or SOURCE_DATE_EPOCH)",
    )
    args = parser.parse_args()
    if args.source_date_epoch is None:
        parser.error("--source-date-epoch or SOURCE_DATE_EPOCH is required")
    try:
        epoch = parse_source_date_epoch(args.source_date_epoch)
        digest = create_archive(
            input_path=args.input,
            archive_name=args.archive_name,
            output_path=args.output,
            source_date_epoch=epoch,
        )
    except ValueError as error:
        parser.error(str(error))
    print(f"{digest}  {args.output.name}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
