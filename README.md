# Local Email Phishing Analyzer

A local Streamlit app for the thesis topic: read-only IMAP mailbox analysis,
phishing risk scores with reasons, feature-group comparison, and cross-dataset
evaluation using precision and recall.

## Requirements and startup

Python 3.9 or newer:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
streamlit run app.py
```

Open the local URL printed by Streamlit (normally
`http://127.0.0.1:8501`). Keep that terminal open while using the app; press
`Ctrl+C` there to stop it. The app binds only to localhost and disables
Streamlit usage statistics. If the optional first-run email prompt appears,
you can leave it blank.

The interface is served locally by Streamlit. It does not send email or model
data to a hosted service. Project settings disable Streamlit usage statistics
and bind the server to `127.0.0.1`, so it is available only from this computer.
If you see the first-run onboarding prompt, you can leave the email field blank.

On macOS Python builds that use LibreSSL, the dependency constraint keeps
urllib3 on its 1.x line to avoid urllib3 2.x's OpenSSL compatibility warning.

## Run the tests

From the project directory, with the project dependencies installed:

```bash
python3 -m unittest discover -s tests -v
```

The tests cover feature extraction and indicator reasons, held-out and
cross-dataset evaluation, small-dataset validation, and the IMAP client's
read-only selection and `BODY.PEEK[]` fetch behavior. They use synthetic
in-memory messages and a mocked IMAP server; they do not connect to a real
mailbox.

## Try the app with the included test email

Install the starter dataset (one time):

```bash
python3 scripts/install_starter_dataset.py
```

Start or refresh the app. In the sidebar, select `starter_public_corpus` and
click **Train analysis model**. After the success message, scroll to
**Analyze one .eml test message**, click **Browse files**, and choose
`weekend-hiking-plans.eml` in the project directory. Its risk score and
indicator-based reasons appear below the upload field. This sample is an
ordinary illustrative email, not a labeled training example. The score is
only a prototype output and must not be interpreted as a definitive safety
verdict.

To see feature-group results, click **Compare feature groups and models**
under **Research evaluation**. The app reports precision and recall for
headers, links, and wording features with logistic regression and random
forest.

## Architecture and use cases

`app.py` provides the local web interface. `phishing_analyzer/imap_client.py`
handles the read-only mailbox connection; `datasets.py` parses the labeled
`.eml` files; `email_features.py` extracts the three feature groups and
human-readable indicators; and `evaluation.py` trains models and computes
research metrics. The `EmailRecord` data model holds one dataset name, binary
label, and extracted feature groups. Training and mailbox inspection are
separate use cases: the live mailbox is never used as training data.

The user can (1) train a classifier on one public dataset, (2) compare feature
groups on a held-out split, (3) test generalization on another dataset, (4)
score a mailbox read-only, or (5) upload one `.eml` as a manual test case.

## Prepare public datasets

The application uses `.eml` files only as labeled training and test examples.
Organize each public dataset into its own directory, with class labels in the
subdirectory names:

```text
data/datasets/
  dataset_one/
    phishing/
      message-001.eml
    legitimate/
      message-002.eml
  dataset_two/
    phishing/
    legitimate/
```

`phish`/`spam` and `ham`/`benign` are also accepted labels. Keep independently
sourced datasets in separate directories for a meaningful cross-dataset test.
The loader expects raw `.eml` files and does not infer labels from message
content. Use datasets whose licenses and terms permit academic use.

### Install a starter dataset

To try model training without first arranging a dataset yourself, run:

```bash
python3 scripts/install_starter_dataset.py
```

This downloads 100 phishing messages from the pinned
[Phishing Pot corpus](https://github.com/rf-peixoto/phishing_pot) and 100
non-spam (“easy ham”) messages from the
[Apache SpamAssassin public corpus](https://spamassassin.apache.org/old/publiccorpus/).
The files are placed in `data/datasets/starter_public_corpus/` and are excluded
from version control. Refresh the Streamlit page afterward; the dataset should
then appear in the sidebar and enable **Train analysis model**.

This starter set is only to exercise the application. It combines two sources,
the SpamAssassin messages are from 2003 and mean “non-spam” rather than
independently verified benign, and the Phishing Pot dataset card and top-level
license differ. See the generated `SOURCE.txt` in the dataset directory.
Check the source terms with your supervisor before using or publishing results.
Do not treat its metrics as thesis findings. For final research, prepare larger
and appropriately licensed public datasets, document their exact versions and
labels, and use a separate independently sourced dataset for cross-dataset
testing.

## Research evaluation

The within-dataset evaluation uses one stratified 75/25 train/test split and
reports phishing-class precision and recall for headers, links, and wording,
with both logistic regression and random forest. The cross-dataset evaluation
trains each feature-group/model pair on all messages in the selected source
dataset, then tests it on the separate target dataset. No target examples are
used for model fitting.

Precision answers what fraction of flagged messages are phishing; recall
answers what fraction of phishing messages are detected. A single split can
vary with dataset composition. Do not select features or tune thresholds on
the cross-dataset test set. Public datasets can contain duplicates or source
artifacts, so deduplicate and document dataset provenance before interpreting
results. The app does not claim that a high score establishes that an email is
phishing; use the score as a triage aid.

## Features and explanations

The analysis groups are:

* **Headers:** sender/Reply-To/Return-Path domain mismatches and available
  SPF/DKIM/DMARC results.
* **Links:** URL/domain count, sender-domain mismatch, IP-literal hosts,
  shortened links, punycode, user information, and HTTPS use.
* **Wording:** urgency/account terms, body length, capitalization, and
  punctuation.

The reported probability comes from the fitted classifier. Reasons are
human-readable indicators extracted from the same three groups; they are not
formal feature-attribution explanations and may not explain every model
prediction.

## IMAP and privacy

Use the mailbox provider's IMAP SSL host and an app password where supported.
The app connects over IMAP SSL, opens the selected folder with read-only
selection, searches message IDs, and fetches message bodies using
`BODY.PEEK[]` so inspection does not mark them as read. It does not delete,
move, flag, or send messages. Credentials are entered for a connection and
are not written to a configuration file or database; the password field can
remain in the active Streamlit session's memory until that session ends.
Avoid shared computers and close the app session when finished. OAuth is provider-specific and is not
implemented in this prototype; use a provider-supported app password or add a
provider-specific OAuth flow before deployment where app passwords are
unavailable.

Email contains personal data. Obtain authorization, minimize retained samples,
follow dataset and mailbox terms, restrict local file permissions, and apply
your institution's GDPR/data-protection requirements. Training datasets stay
on the local machine; the user-provided mailbox contents are processed in
memory for the current app session.
