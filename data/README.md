# Data notes

`email_samples.csv` is a small synthetic dataset intended only to demonstrate the end-to-end workflow. It is not a representative phishing corpus and should not be used to claim real-world accuracy.

For a serious evaluation:
1. Obtain a properly licensed public dataset with labels.
2. Deduplicate near-identical messages.
3. Split train/test by source or time where possible to reduce leakage.
4. Evaluate on a held-out set containing human-written and LLM-generated phishing AND legitimate emails.
5. Report precision, recall, F1, false-positive rate, and subgroup results.
