import csv
import json

from scripts.training.make_open_corpus_iter3_dataset import build_dataset


def test_open_corpus_iter3_dataset_is_separate_and_metadata_only(tmp_path):
    cve_path = tmp_path / "cve.jsonl"
    cve_path.write_text(
        "\n".join(
            [
                json.dumps(
                    {
                        "cwe": ["CWE-79"],
                        "desc": "A web application cross site scripting issue allows script injection.",
                        "id": "CVE-2099-0001",
                        "severity": "HIGH",
                    }
                ),
                json.dumps(
                    {
                        "cwe": ["CWE-285"],
                        "desc": "An API authorization flaw allows access to another test record.",
                        "id": "CVE-2099-0002",
                        "severity": "MEDIUM",
                    }
                ),
            ]
        )
        + "\n",
        encoding="utf-8",
    )

    exploitdb_path = tmp_path / "files_exploits.csv"
    with exploitdb_path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(
            handle,
            fieldnames=[
                "id",
                "file",
                "description",
                "date_published",
                "author",
                "type",
                "platform",
                "port",
                "date_added",
                "date_updated",
                "verified",
                "codes",
                "tags",
                "aliases",
                "screenshot_url",
                "application_url",
                "source_url",
            ],
        )
        writer.writeheader()
        writer.writerow(
            {
                "description": "Example CMS 1.2 - public exploit reference",
                "id": "50000",
                "platform": "php",
                "tags": "cms,webapps",
                "type": "webapps",
                "verified": "1",
            }
        )

    manifest = build_dataset(
        out_dir=tmp_path,
        prefix="aegispt_open_corpus_iter3",
        cve_jsonl=cve_path,
        exploitdb_csv=exploitdb_path,
        counts={"train": 1, "eval": 1, "test": 1},
        seed=1,
    )

    assert manifest["does_not_modify"] == "aegispt_full_coverage_dora_loraplus_unsloth"
    assert manifest["policy"]["exploitdb_mode"] == "metadata_only"
    assert manifest["policy"]["raw_poc_code"] == "not_read_or_written"

    rows = []
    for split in ("train", "eval", "test"):
        path = tmp_path / f"aegispt_open_corpus_iter3_{split}.jsonl"
        assert path.exists()
        rows.extend(json.loads(line) for line in path.read_text(encoding="utf-8").splitlines())

    assert {row["metadata"]["source"] for row in rows} == {"exploitdb_metadata", "nvd_cve_2026"}
    assert any("no_poc_code" in row["metadata"]["safety_tags"] for row in rows)
    assert all("aegispt_full_coverage_dora_loraplus_unsloth" not in row["metadata"]["case_id"] for row in rows)
