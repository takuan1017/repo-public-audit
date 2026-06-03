# Public Release Checklist

Before making a repository public:

- Review the current tree for secrets and private data.
- Review Git history for credentials or sensitive documents.
- Remove or redact business-specific data that does not belong in OSS.
- Add a license.
- Add a README with purpose, install, usage, and limitations.
- Add a security policy.
- Add contribution guidance if you want outside help.
- Rotate any credential that may have been committed, even if it was later deleted.

If the repository has ever contained secrets, the safest path is often to create a new clean repository and copy only the public-safe files.

