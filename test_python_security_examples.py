import stat
import unittest
from pathlib import Path

import python_security_examples as examples


class PythonSecurityExamplesTest(unittest.TestCase):
    def setUp(self) -> None:
        examples.setup_demo_db()
        examples.INSECURE_OUTPUT_DIR.mkdir(exist_ok=True)
        examples.SECURE_OUTPUT_DIR.mkdir(exist_ok=True)

    def tearDown(self) -> None:
        if examples.DB_PATH.exists():
            examples.DB_PATH.unlink()

        for directory in (examples.INSECURE_OUTPUT_DIR, examples.SECURE_OUTPUT_DIR):
            if directory.exists():
                for path in sorted(directory.rglob("*"), reverse=True):
                    if path.is_file():
                        path.unlink()
                    elif path.is_dir():
                        path.rmdir()
                directory.rmdir()

        escaped_report = Path(__file__).with_name("shared")
        if escaped_report.exists():
            for path in sorted(escaped_report.rglob("*"), reverse=True):
                if path.is_file():
                    path.unlink()
                elif path.is_dir():
                    path.rmdir()
            escaped_report.rmdir()

    def test_insecure_query_is_injectable_but_secure_query_is_not(self) -> None:
        injected_username = "' OR '1'='1"

        insecure_rows = examples.insecure_find_user(injected_username)
        secure_rows = examples.secure_find_user(injected_username)

        self.assertEqual(len(insecure_rows), 2)
        self.assertEqual(secure_rows, [])

    def test_secure_and_insecure_profile_loaders_are_separated(self) -> None:
        encoded_pickle, encoded_json = examples.build_demo_payload()

        self.assertEqual(
            examples.insecure_load_profile(encoded_pickle),
            {"name": "Alice", "language": "Python"},
        )
        self.assertEqual(
            examples.secure_load_profile(encoded_json),
            {"name": "Alice", "language": "Python"},
        )

    def test_secure_password_digest_uses_salt_prefix(self) -> None:
        insecure = examples.insecure_password_digest("ResearchPassword!")
        secure = examples.secure_password_digest(
            "ResearchPassword!",
            salt=b"0123456789ABCDEF",
        )

        self.assertEqual(len(insecure), 32)
        self.assertTrue(secure.startswith("30313233343536373839414243444546:"))
        self.assertGreater(len(secure), len(insecure))

    def test_secure_report_write_stays_in_directory_and_uses_0600(self) -> None:
        insecure_path = examples.insecure_save_report("../shared/report.txt", "draft findings")
        secure_path = examples.secure_save_report("../shared/report.txt", "draft findings")

        self.assertEqual(insecure_path.resolve(), Path(__file__).with_name("shared").joinpath("report.txt").resolve())
        self.assertEqual(secure_path.parent.resolve(), examples.SECURE_OUTPUT_DIR.resolve())
        self.assertEqual(stat.S_IMODE(secure_path.stat().st_mode), 0o600)


if __name__ == "__main__":
    unittest.main()
