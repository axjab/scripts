"""Hardware-free regression tests for auth."""
import contextlib
import io
import pathlib
import runpy
import types
import unittest
from unittest.mock import patch

auth = types.SimpleNamespace(**runpy.run_path(str(pathlib.Path(__file__).resolve().parents[1] / "bin/auth.py")))
G = auth.main.__globals__


def credential(name, kind="TOTP", touch=False, period=30):
    return types.SimpleNamespace(id=name.encode(), oath_type=types.SimpleNamespace(name=kind),
                                 issuer=None, touch_required=touch, period=period)


class Credential:
    def __init__(self, name, kind="TOTP", touch=False, period=30):
        self.__dict__.update(credential(name, kind, touch, period).__dict__)

    def __lt__(self, other):
        return self.id < other.id


class AuthTests(unittest.TestCase):
    def test_aliases(self):
        self.assertEqual(auth.parse(["ls"])[0], "list")
        self.assertEqual(auth.parse(["remove", "x"])[0], "rm")

    def test_unique(self):
        a, b = credential("Example"), credential("Example 2")
        self.assertIs(auth.resolve([a, b], "2"), b)
        with self.assertRaises(auth.AuthError):
            auth.resolve([a, b], "Example")
        with self.assertRaises(auth.AuthError):
            auth.resolve([a, b], "absent")

    def test_only_hotp_never_calculates_individual(self):
        c = Credential("Counter", "HOTP")
        class Session:
            def calculate_all(self, timestamp):
                return {c: None}
        self.assertEqual(auth.fetch_codes(Session(), 60)[0][1], "HOTP - on demand only")

    def test_touch_not_triggered_by_bulk(self):
        c = Credential("Touch", touch=True)
        class Session:
            def calculate_all(self, timestamp):
                return {c: None}
        self.assertEqual(auth.fetch_codes(Session(), 60)[0][1], "Touch required")

    def test_periods_and_leading_zeroes(self):
        a, b = Credential("A"), Credential("B", period=60)
        class Session:
            def calculate_all(self, timestamp):
                return {a: types.SimpleNamespace(value="000001", valid_from=30, valid_to=60),
                        b: types.SimpleNamespace(value="123456", valid_from=0, valid_to=60)}
        rows = auth.fetch_codes(Session(), 59)
        self.assertIn("000001  1s", auth.render(rows, 59)[1])
        self.assertFalse(auth.needs_refresh(rows, 59))
        self.assertTrue(auth.needs_refresh(rows, 60))
        self.assertTrue(auth.needs_refresh(rows, 29))
        self.assertNotIn("000001", auth.render(rows, 60)[1])

    def test_terminal_no_clear(self):
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            auth.draw(["first", "second"], 2, 80)
        value = out.getvalue()
        self.assertIn("\x1b[2A", value)
        for forbidden in ("\x1b[2J", "\x1b[3J", "\x1b[?1049h"):
            self.assertNotIn(forbidden, value)

    def test_non_tty_snapshot(self):
        out = io.StringIO()
        with patch.dict(G, {"terminal": lambda: False,
                            "fetch_codes": lambda *args: [("Example", "000001", 0, 30)],
                            "time": types.SimpleNamespace(time=lambda: 1)}), contextlib.redirect_stdout(out):
            auth.watch(None, None)
        self.assertIn("000001", out.getvalue())
        self.assertNotIn("\x1b", out.getvalue())

    def test_policy(self):
        info = "Enabled USB interfaces: FIDO, CCID\nNFC transport is enabled\nApplications USB NFC\n"
        info += "\n".join(f"{a} {v} {v}" for a, v in auth.POLICY.items())
        self.assertEqual(len(auth.compare_info(info)), 16)
        self.assertTrue(all(r[1] == "OK" for r in auth.compare_info(info)))
        changed = info.replace("FIDO2 Enabled Enabled", "FIDO2 Disabled Not available")
        results = {r[0]: r[1] for r in auth.compare_info(changed)}
        self.assertEqual(results["FIDO2 / USB"], "MISMATCH")
        self.assertEqual(results["FIDO2 / NFC"], "UNSUPPORTED")
        self.assertTrue(all(r[1] == "UNKNOWN" for r in auth.compare_info("")))

    def test_single_transport(self):
        rows = auth.compare_info("Applications\nFIDO2 Enabled")
        self.assertIn(("FIDO2 / USB", "OK", "Enabled", "Enabled"), rows)
        self.assertIn(("FIDO2 / NFC", "UNKNOWN", "not reported", "Enabled"), rows)

    def test_read_allowlist(self):
        for cmd in [("config", "usb"), ("fido", "credentials", "delete"),
                    ("openpgp", "keys", "set-touch"), ("oath", "accounts", "code")]:
            with self.assertRaises(auth.AuthError):
                auth.backend(cmd)

    def test_multi_key_requires_selection(self):
        with patch.dict(G, {"serials": lambda: ["1", "2"]}):
            with self.assertRaises(auth.AuthError):
                auth.select_serial(None)
            self.assertEqual(auth.select_serial("2"), "2")

    def test_sanitize(self):
        self.assertEqual(auth.safe("a\x1b[2J"), "a?[2J")


if __name__ == "__main__":
    unittest.main()
