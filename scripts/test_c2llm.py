import unittest
from c2llm_service import validate_request, MODEL, MAX_BATCH
from c2llm_retrieval import reciprocal_rank_fusion, file_stamp, embed
from pathlib import Path
import tempfile

class C2LLMContractTests(unittest.TestCase):
    def test_request_limits_and_model_isolation(self):
        self.assertEqual(validate_request({'model': MODEL, 'input': 'query'}), ['query'])
        for payload in [{'model':'nomic-embed-text','input':'query'}, {'input':[]},
                        {'input':['query']*(MAX_BATCH+1)}, {'input':'x'*16001}, {'input':[None]}]:
            with self.assertRaises(ValueError):validate_request(payload)

    def test_rrf_deduplicates_each_lane_and_uses_deterministic_ties(self):
        ranked=reciprocal_rank_fusion([['b','b','a'],['a','c']])
        self.assertEqual(ranked[0][0],'a')
        self.assertAlmostEqual(dict(ranked)['b'],1/61)
        self.assertEqual(reciprocal_rank_fusion([['b'],['a']])[0][0],'a')

    def test_code_embeddings_reject_hosted_endpoints(self):
        with self.assertRaises(ValueError):embed('https://example.com', 'private source')

    def test_file_stamp_invalidates_edits_and_deletions(self):
        with tempfile.TemporaryDirectory() as folder:
            path=Path(folder)/'a.rs';path.write_text('old')
            before=file_stamp(path);path.write_text('newer')
            self.assertNotEqual(before,file_stamp(path))
            path.unlink();self.assertIsNone(file_stamp(path))

if __name__=='__main__':unittest.main()
