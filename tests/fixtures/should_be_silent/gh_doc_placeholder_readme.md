# Revoking a personal access token via the API

This project's CI cleanup job revokes stale tokens through GitHub's REST API.
The request body shape is the same one GitHub's own documentation uses to
illustrate the endpoint:

    curl -X DELETE \
      -H "Authorization: Bearer <YOUR-TOKEN>" \
      https://api.github.com/applications/<client_id>/token \
      -d '{"access_token":"ghp_1234567890abcdef1234567890abcdef12345678"}'

**Do not commit real tokens to source control.** The value above is
reproduced verbatim from GitHub's own REST API reference
(docs.github.com/en/rest/credentials/revoke, "Revoke a personal access
token") purely to show the expected request shape — it is not a live
token and never has been.

Store your actual values in your CI provider's encrypted secrets store
instead, and reference them from there.
