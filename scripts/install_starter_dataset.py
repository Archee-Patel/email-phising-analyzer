"""Install a small public .eml dataset subset for local app testing."""

import json
import tarfile
from pathlib import Path
from typing import Dict, Iterable, List
from urllib.parse import quote
from urllib.request import Request, urlopen


ROOT = Path(__file__).resolve().parents[1]
DATASET = ROOT / "data" / "datasets" / "starter_public_corpus"
PHISHING_REPOSITORY = "rf-peixoto/phishing_pot"
PHISHING_COMMIT = "2933c0341b1248678c1e246b36d352add2edf0f1"
PHISHING_COUNT = 100
MAX_EMAIL_BYTES = 100_000
SPAMASSASSIN_ARCHIVE = (
    "https://spamassassin.apache.org/old/publiccorpus/"
    "20030228_easy_ham.tar.bz2"
)


def _read_url(url: str, max_bytes: int) -> bytes:
    request = Request(url, headers={"User-Agent": "local-email-phishing-analyzer"})
    with urlopen(request, timeout=30) as response:
        payload = response.read(max_bytes + 1)
    if len(payload) > max_bytes:
        raise ValueError("Download exceeded the expected size limit: {}".format(url))
    return payload


def _phishing_files() -> List[Dict[str, object]]:
    tree_url = (
        "https://api.github.com/repos/{}/git/trees/{}?recursive=1"
        .format(PHISHING_REPOSITORY, PHISHING_COMMIT)
    )
    tree = json.loads(_read_url(tree_url, 5_000_000).decode("utf-8"))
    if tree.get("truncated"):
        raise ValueError("The public phishing dataset listing was truncated.")
    candidates = [
        item for item in tree.get("tree", [])
        if item.get("path", "").startswith("email/")
        and item.get("path", "").endswith(".eml")
        and 100 <= item.get("size", MAX_EMAIL_BYTES + 1) <= MAX_EMAIL_BYTES
    ]
    return sorted(candidates, key=lambda item: item["path"])[:PHISHING_COUNT]


def _save_phishing_samples(directory: Path) -> int:
    directory.mkdir(parents=True, exist_ok=True)
    count = 0
    for index, item in enumerate(_phishing_files(), start=1):
        relative_path = quote(str(item["path"]), safe="/")
        url = "https://raw.githubusercontent.com/{}/{}/{}".format(
            PHISHING_REPOSITORY, PHISHING_COMMIT, relative_path
        )
        payload = _read_url(url, MAX_EMAIL_BYTES)
        if b"\n" not in payload or b":" not in payload.split(b"\n", 1)[0]:
            raise ValueError("Downloaded phishing sample is not an email message.")
        (directory / "phishing-{:03d}.eml".format(index)).write_bytes(payload)
        count += 1
    return count


def _ham_members(archive: bytes) -> Iterable[tuple]:
    import io

    with tarfile.open(fileobj=io.BytesIO(archive), mode="r:bz2") as corpus:
        members = [
            member for member in corpus.getmembers()
            if member.isfile()
            and member.name.startswith("easy_ham/")
            and member.size <= MAX_EMAIL_BYTES
        ]
        for member in sorted(members, key=lambda item: item.name):
            fileobj = corpus.extractfile(member)
            if fileobj is None:
                continue
            yield member.name, fileobj.read(MAX_EMAIL_BYTES + 1)


def _save_ham_samples(directory: Path) -> int:
    archive = _read_url(SPAMASSASSIN_ARCHIVE, 10_000_000)
    directory.mkdir(parents=True, exist_ok=True)
    count = 0
    for name, payload in _ham_members(archive):
        if len(payload) > MAX_EMAIL_BYTES:
            continue
        if b"\n" not in payload or b":" not in payload.split(b"\n", 1)[0]:
            continue
        count += 1
        (directory / "legitimate-{:03d}.eml".format(count)).write_bytes(payload)
        if count == PHISHING_COUNT:
            break
    return count


def main() -> None:
    if DATASET.exists() and any(DATASET.rglob("*.eml")):
        raise SystemExit(
            "{} already contains .eml files; refusing to overwrite it."
            .format(DATASET)
        )

    phishing_dir = DATASET / "phishing"
    legitimate_dir = DATASET / "legitimate"
    try:
        phishing_count = _save_phishing_samples(phishing_dir)
        ham_count = _save_ham_samples(legitimate_dir)
        if phishing_count < 4 or ham_count < 4:
            raise ValueError(
                "Not enough samples downloaded ({} phishing, {} legitimate)."
                .format(phishing_count, ham_count)
            )
    except Exception:
        for path in DATASET.rglob("*.eml"):
            path.unlink()
        raise

    source_note = """Starter dataset installed for local app testing.

Phishing samples: Phishing Pot, commit {commit}
  https://github.com/rf-peixoto/phishing_pot
  Dataset card declares CC BY-NC 4.0; attribution required. The repository's
  top-level license differs from that declaration, so verify usage terms
  with the dataset maintainer before redistributing samples or publishing.
  Attribution: https://github.com/rf-peixoto/phishing_pot and
  https://www.linkedin.com/in/rf-peixoto

Legitimate/non-spam samples: Apache SpamAssassin public corpus,
  20030228_easy_ham (2003).
  https://spamassassin.apache.org/old/publiccorpus/
  The corpus documentation states that message text remains copyrighted by
  the original senders. Use only for permitted research and do not redistribute.

This balanced subset is a starter test corpus, not a representative or
publication-ready benchmark. The easy_ham class means non-spam, not a guarantee
that each email is benign. Record sources and versions in any thesis results.
""".format(commit=PHISHING_COMMIT)
    (DATASET / "SOURCE.txt").write_text(source_note, encoding="utf-8")
    print(
        "Installed {} phishing and {} non-spam .eml samples in {}"
        .format(phishing_count, ham_count, DATASET)
    )


if __name__ == "__main__":
    main()
