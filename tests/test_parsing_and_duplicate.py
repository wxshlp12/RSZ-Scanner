import unittest
import random

import main
import secp256k1 as ice


class ParsingAndDuplicateTests(unittest.TestCase):
    def test_get_rs_handles_sighash(self):
        # DER: 30 06 02 01 01 02 01 01 + sighash 01
        sig = "300602010102010101"
        r, s = main.get_rs(sig)
        self.assertEqual(r, "01")
        self.assertEqual(s, "01")

    def test_parse_and_signable_witness(self):
        # Synthetic 1-in-1-out segwit tx with simple witness stack
        version = "01000000"
        markerflag = "0001"
        vin_count = "01"
        prev = "00" * 32
        vout = "ffffffff"
        script_len = "00"
        seq = "ffffffff"
        vout_count = "01"
        value = "0100000000000000"
        pk_script = "76a914" + "00" * 20 + "88ac"
        pk_len = "19"
        w_count = "02"
        w1 = "300602010102010101"  # der + sighash
        w1_len = "09"
        w2 = "02" + "01" * 64  # compressed pubkey
        w2_len = "21"
        locktime = "00000000"
        raw = (
            version
            + markerflag
            + vin_count
            + prev
            + vout
            + script_len
            + seq
            + vout_count
            + value
            + pk_len
            + pk_script
            + w_count
            + w1_len
            + w1
            + w2_len
            + w2
            + locktime
        )
        parsed = main.parse_transaction(raw)
        self.assertTrue(parsed["segwit"])
        self.assertEqual(parsed["inputs"][0]["r"], "01")
        self.assertEqual(parsed["inputs"][0]["s"], "01")
        self.assertTrue(parsed["inputs"][0]["pub"].startswith("02"))
        z_entries = main.get_signable_transaction(
            parsed, {0: {"value": 1, "scriptpubkey": "0014" + "00" * 20}}
        )
        self.assertEqual(len(z_entries), 1)
        self.assertIsInstance(int(z_entries[0][2], 16), int)

    def test_duplicate_r_detection(self):
        pvk = random.randrange(1, ice.N - 1)
        k = random.randrange(1, ice.N - 1)
        Q = ice.scalar_multiplication(pvk)
        r_point = ice.scalar_multiplication(k)
        r = int(r_point[1:33].hex(), 16)
        # reuse nonce to force duplicate R
        z1 = random.randrange(1, ice.N - 1)
        z2 = random.randrange(1, ice.N - 1)
        inv_k = pow(k, ice.N - 2, ice.N)
        s1 = (inv_k * (z1 + r * pvk)) % ice.N
        s2 = (inv_k * (z2 + r * pvk)) % ice.N
        rL = [r, r]
        sL = [s1, s2]
        zL = [z1, z2]
        QL = [Q, Q]
        RQ = [main.calc_RQ(r, s1, z1, Q), main.calc_RQ(r, s2, z2, Q)]
        rd = main.diff_comb_idx(RQ)
        self.assertTrue(any(d[2] == ice.Zero for d in rd))


if __name__ == "__main__":
    unittest.main()
