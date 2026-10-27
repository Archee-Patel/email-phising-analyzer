from email import policy
from email.parser import BytesParser
import imaplib
from pathlib import Path
from typing import Optional

import pandas as pd
import streamlit as st

from phishing_analyzer.datasets import discover_datasets, load_dataset
from phishing_analyzer.email_features import explain_features, extract_feature_groups
from phishing_analyzer.evaluation import (
    MODEL_NAMES,
    TrainedModel,
    evaluate_cross_dataset,
    evaluate_within_dataset,
    train_model,
)
from phishing_analyzer.imap_client import fetch_recent_messages


st.set_page_config(page_title="Local Phishing Analyzer", page_icon="✉️", layout="wide")
st.title("Local Email Phishing Analyzer")
st.caption(
    "Analyzes locally held email data and connects to mailboxes over encrypted, "
    "read-only IMAP. Messages and credentials are not uploaded or saved by this app."
)

with st.sidebar:
    st.header("Training datasets")
    dataset_root = Path(st.text_input("Dataset folder", value="data/datasets")).expanduser()
    available = discover_datasets(dataset_root)
    if available:
        dataset_names = [name for name, _ in available]
        selected_dataset = st.selectbox("Dataset for analysis", dataset_names)
        dataset_paths = dict(available)
        if (dataset_paths[selected_dataset] / "SOURCE.txt").is_file():
            st.warning(
                "This is a starter dataset for app testing, not thesis-grade "
                "evidence. Review its SOURCE.txt before using the data."
            )
    else:
        selected_dataset = None
        dataset_paths = {}
        st.info("No labeled .eml datasets found at this path.")
    model_name = st.selectbox("Model", MODEL_NAMES)
    if st.button("Train analysis model", disabled=selected_dataset is None):
        try:
            with st.spinner("Loading .eml files and training model..."):
                selected_records = load_dataset(dataset_paths[selected_dataset])
                st.session_state["trained_model"] = train_model(
                    selected_records, model_name
                )
                st.session_state["trained_dataset"] = selected_dataset
                st.session_state["trained_model_name"] = model_name
                st.session_state["trained_records"] = selected_records
            st.success("Model trained on {} emails.".format(len(selected_records)))
        except (OSError, ValueError) as error:
            st.error(str(error))

st.header("Research evaluation")
if len(available) >= 1:
    evaluation_dataset = st.selectbox(
        "Dataset for within-dataset comparison",
        [name for name, _ in available],
        key="within_dataset",
    )
    if st.button("Compare feature groups and models"):
        st.session_state.pop("within_results", None)
        try:
            records = load_dataset(dataset_paths[evaluation_dataset])
            result = evaluate_within_dataset(records)
            st.session_state["within_results"] = result
            st.session_state["within_source"] = evaluation_dataset
        except (OSError, ValueError) as error:
            st.error(str(error))
    if "within_results" in st.session_state:
        st.caption("Evaluation dataset: {}".format(st.session_state["within_source"]))
        st.write(
            "Stratified 75/25 train/test split. Precision and recall measure "
            "phishing detection on the held-out portion."
        )
        st.dataframe(
            st.session_state["within_results"].style.format(
                {"Precision": "{:.3f}", "Recall": "{:.3f}"}
            ),
            use_container_width=True,
        )
        results = st.session_state["within_results"]
        recall_winner = results.loc[results["Recall"].idxmax()]
        precision_winner = results.loc[results["Precision"].idxmax()]
        st.write(
            "**Highest recall:** {} with {} "
            "(precision {:.3f}, recall {:.3f}).".format(
                recall_winner["Feature group"],
                recall_winner["Model"],
                recall_winner["Precision"],
                recall_winner["Recall"],
            )
        )
        st.write(
            "**Highest precision:** {} with {} "
            "(precision {:.3f}, recall {:.3f}).".format(
                precision_winner["Feature group"],
                precision_winner["Model"],
                precision_winner["Precision"],
                precision_winner["Recall"],
            )
        )

if len(available) >= 2:
    st.subheader("Cross-dataset evaluation")
    dataset_names = [name for name, _ in available]
    source = st.selectbox("Train on", dataset_names, key="cross_source")
    target_options = [name for name in dataset_names if name != source]
    target = st.selectbox("Test on a different dataset", target_options, key="cross_target")
    if st.button("Run cross-dataset test"):
        st.session_state.pop("cross_results", None)
        try:
            with st.spinner("Loading the two datasets..."):
                source_records = load_dataset(dataset_paths[source])
                target_records = load_dataset(dataset_paths[target])
                cross_results = evaluate_cross_dataset(source_records, target_records)
                st.session_state["cross_results"] = cross_results
            st.success("Cross-dataset evaluation complete.")
        except (OSError, ValueError) as error:
            st.error(str(error))
    if "cross_results" in st.session_state:
        st.write(
            "Each model is trained only on the source dataset and evaluated "
            "on the separate target dataset."
        )
        st.dataframe(
            st.session_state["cross_results"].style.format(
                {"Precision": "{:.3f}", "Recall": "{:.3f}"}
            ),
            use_container_width=True,
        )
        results = st.session_state["cross_results"]
        recall_winner = results.loc[results["Recall"].idxmax()]
        st.write(
            "**Highest cross-dataset recall:** {} with {} "
            "(precision {:.3f}, recall {:.3f}).".format(
                recall_winner["Feature group"],
                recall_winner["Model"],
                recall_winner["Precision"],
                recall_winner["Recall"],
            )
        )
elif available:
    st.info("Add a second labeled dataset to run the cross-dataset test.")

st.header("Analyze a mailbox")
trained_model: Optional[TrainedModel] = st.session_state.get("trained_model")
if trained_model is None:
    st.info("Train a model from a labeled public .eml dataset before analyzing mail.")
else:
    st.caption(
        "Current model: {} trained on {}.".format(
            st.session_state["trained_model_name"],
            st.session_state["trained_dataset"],
        )
    )
    with st.form("imap_connection"):
        imap_host = st.text_input("IMAP server", placeholder="imap.example.com")
        imap_port = st.number_input("IMAP SSL port", min_value=1, max_value=65535, value=993)
        imap_username = st.text_input("Mailbox username")
        imap_password = st.text_input(
            "App password", type="password", help="Used only for this connection."
        )
        mailbox = st.text_input("Mailbox", value="INBOX")
        message_limit = st.number_input(
            "Recent messages to inspect", min_value=1, max_value=500, value=25
        )
        submitted = st.form_submit_button("Connect and analyze")

    if submitted:
        st.session_state.pop("mailbox_results", None)
        try:
            with st.spinner("Connecting over SSL and fetching messages read-only..."):
                messages = fetch_recent_messages(
                    host=imap_host,
                    username=imap_username,
                    password=imap_password,
                    mailbox=mailbox,
                    limit=int(message_limit),
                    port=int(imap_port),
                )
                analyzed = []
                for item in messages:
                    features = extract_feature_groups(item.message)
                    probability = trained_model.phishing_probability(features)
                    analyzed.append({
                        "UID": item.uid.decode("ascii", errors="replace"),
                        "Subject": str(item.message.get("Subject", "(no subject)")),
                        "From": str(item.message.get("From", "(unknown sender)")),
                        "Phishing risk": probability,
                        "Reasons": "; ".join(explain_features(features)),
                    })
            st.session_state["mailbox_results"] = analyzed
            st.success("Analyzed {} messages.".format(len(analyzed)))
        except (imaplib.IMAP4.error, OSError, ValueError, RuntimeError) as error:
            st.error("Mailbox analysis failed: {}".format(error))

    if "mailbox_results" in st.session_state:
        results = st.session_state["mailbox_results"]
        if results:
            display = pd.DataFrame(results)
            display["Phishing risk"] = display["Phishing risk"].map(
                lambda score: "{:.1f}%".format(score * 100)
            )
            st.dataframe(display, use_container_width=True, hide_index=True)
        else:
            st.info("The selected mailbox contained no messages.")

st.header("Analyze one .eml test message")
uploaded = st.file_uploader("Choose an .eml file", type=["eml"])
if uploaded is not None:
    if trained_model is None:
        st.warning("Train a model before scoring a test message.")
    else:
        message = BytesParser(policy=policy.default).parsebytes(uploaded.getvalue())
        features = extract_feature_groups(message)
        score = trained_model.phishing_probability(features)
        st.metric("Phishing risk", "{:.1f}%".format(score * 100))
        st.write("**Reasons**")
        for reason in explain_features(features):
            st.write("- {}".format(reason))
