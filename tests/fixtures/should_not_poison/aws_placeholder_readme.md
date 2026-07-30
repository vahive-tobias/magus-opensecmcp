# Configuring AWS credentials for the build pipeline

This project's CI job needs read-only access to a private S3 bucket to fetch
prebuilt cache artifacts. Create an IAM user scoped to just that bucket
(`s3:GetObject`, `s3:ListBucket`) and wire the credentials in as environment
variables the same way AWS's own docs illustrate the expected shape:

    AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
    AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
    AWS_DEFAULT_REGION=us-east-1

**Do not commit real credentials to source control.** The pair above is the
well-known placeholder pair from AWS's own documentation, reproduced here
only so contributors can see the expected format — it is not a live key and
never has been.

Store your actual values in your CI provider's encrypted secrets store
instead, and reference them from there.
