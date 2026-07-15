import os
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import app


class SupportFeatureTests(unittest.TestCase):
    def test_demo_links_include_safe_local_malicious_trigger(self):
        links = app.get_demo_links()
        malicious = links["malicious"]

        self.assertEqual(malicious["label"], "Malicious download simulation")
        self.assertTrue(malicious["url"].startswith("http://127.0.0.1:5000/"))
        self.assertTrue(malicious["url"].endswith(".exe"))
        self.assertIn("harmless local", malicious["description"].lower())

    def test_urlhaus_download_url_requires_auth_key_or_override(self):
        self.assertIsNone(app.build_urlhaus_download_url(auth_key="", override_url=""))

        override_url = "https://example.com/urlhaus.csv"
        self.assertEqual(
            app.build_urlhaus_download_url(auth_key="", override_url=override_url),
            override_url,
        )

        download_url = app.build_urlhaus_download_url(
            auth_key="sample-key",
            override_url="",
        )
        self.assertEqual(
            download_url,
            "https://urlhaus-api.abuse.ch/v2/files/exports/sample-key/recent.csv",
        )

    def test_urlhaus_download_url_reads_auth_key_environment_variable(self):
        previous_auth = os.environ.pop("URLHAUS_AUTH_KEY", None)
        previous_csv = os.environ.pop("URLHAUS_CSV_URL", None)

        try:
            os.environ["URLHAUS_AUTH_KEY"] = "sample-key"

            self.assertEqual(
                app.build_urlhaus_download_url(),
                "https://urlhaus-api.abuse.ch/v2/files/exports/sample-key/recent.csv",
            )
        finally:
            os.environ.pop("URLHAUS_AUTH_KEY", None)
            if previous_auth is not None:
                os.environ["URLHAUS_AUTH_KEY"] = previous_auth
            if previous_csv is not None:
                os.environ["URLHAUS_CSV_URL"] = previous_csv

    def test_local_env_loader_reads_values_without_overwriting_existing_env(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            env_path = os.path.join(temp_dir, ".env")
            with open(env_path, "w", encoding="utf-8") as f:
                f.write("URLHAUS_AUTH_KEY=file-key\n")
                f.write("URLHAUS_AUTO_UPDATE=1\n")

            previous_auth = os.environ.get("URLHAUS_AUTH_KEY")
            previous_auto = os.environ.pop("URLHAUS_AUTO_UPDATE", None)
            os.environ["URLHAUS_AUTH_KEY"] = "existing-key"

            try:
                app.load_local_env(env_path)

                self.assertEqual(os.environ["URLHAUS_AUTH_KEY"], "existing-key")
                self.assertEqual(os.environ["URLHAUS_AUTO_UPDATE"], "1")
            finally:
                if previous_auth is None:
                    os.environ.pop("URLHAUS_AUTH_KEY", None)
                else:
                    os.environ["URLHAUS_AUTH_KEY"] = previous_auth

                if previous_auto is None:
                    os.environ.pop("URLHAUS_AUTO_UPDATE", None)
                else:
                    os.environ["URLHAUS_AUTO_UPDATE"] = previous_auto

    def test_urlhaus_ca_bundle_can_be_configured_from_environment(self):
        previous_bundle = os.environ.pop("URLHAUS_CA_BUNDLE", None)

        try:
            os.environ["URLHAUS_CA_BUNDLE"] = "C:\\certs\\cacert.pem"

            self.assertEqual(
                app.get_urlhaus_ca_bundle_path(),
                "C:\\certs\\cacert.pem",
            )
        finally:
            os.environ.pop("URLHAUS_CA_BUNDLE", None)
            if previous_bundle is not None:
                os.environ["URLHAUS_CA_BUNDLE"] = previous_bundle

    def test_urlhaus_ssl_error_message_explains_certificate_fix(self):
        message = app.format_urlhaus_download_error(
            Exception("[SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed")
        )

        self.assertIn("SSL certificate verification failed", message)
        self.assertIn("pip install -r Backend/requirements.txt", message)

    def test_urlhaus_status_reports_loaded_counts_and_configuration(self):
        previous_auth = os.environ.pop("URLHAUS_AUTH_KEY", None)
        previous_csv = os.environ.pop("URLHAUS_CSV_URL", None)
        app.URLHAUS_SET = {"http://malware.test/payload.exe"}
        app.URLHAUS_DOMAINS = {"malware.test"}
        app.URLHAUS_LAST_ERROR = None

        try:
            status = app.get_urlhaus_status(source_path=os.path.join("Data", "missing.csv"))
        finally:
            if previous_auth is not None:
                os.environ["URLHAUS_AUTH_KEY"] = previous_auth
            if previous_csv is not None:
                os.environ["URLHAUS_CSV_URL"] = previous_csv

        self.assertEqual(status["loaded_urls"], 1)
        self.assertEqual(status["loaded_domains"], 1)
        self.assertFalse(status["update_configured"])
        self.assertIsNone(status["last_error"])

    def test_urlhaus_requires_exact_url_match_for_shared_domains(self):
        app.URLHAUS_SET = {"https://www.google.com/malicious/payload.exe"}
        app.URLHAUS_DOMAINS = {"www.google.com"}

        self.assertTrue(app.check_urlhaus("https://www.google.com/malicious/payload.exe"))
        self.assertFalse(
            app.check_urlhaus("https://www.google.com/search?q=whatsapp+web")
        )


if __name__ == "__main__":
    unittest.main()
