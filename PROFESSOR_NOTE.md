# Message to send

Hi Professor,

I have built an early local prototype of my email phishing-analysis project
with AI assistance. It uses labeled `.eml` datasets to train a classifier and
can inspect an email for header, link, and wording indicators, then display a
phishing-risk score with reasons. The app can also compare feature groups
using precision and recall.

To try it, please see the README for setup instructions. After installing the
starter dataset and training the model, upload `weekend-hiking-plans.eml` in
the **Analyze one .eml test message** section. That message is an illustrative
test email; it is not used as training data. The starter dataset is only for
testing the app workflow, not for thesis conclusions. The project also
includes unit tests that can be run with `python3 -m unittest discover -s
tests -v`.

The goal is to explore whether the prototype identifies potential phishing
indicators, not to make a definitive claim that an email is safe or malicious.
I would appreciate your feedback on the research scope, dataset selection,
and evaluation design before I use any results in the thesis.

Best,
Patel
