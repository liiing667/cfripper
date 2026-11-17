# Conditional templates and unknown values

CloudFormation policies frequently rely on intrinsic functions such as
`Fn::If`, `Fn::Sub` and `Fn::Join` to build a `Principal` or `Resource`:

```json
{
  "Principal": {
    "AWS": { "Fn::If": ["IsProd", "arn:aws:iam::123456789012:root", "*"] }
  }
}
```

The static rules only understand plain strings. Without expansion the function
is an opaque dictionary, so a rule can see the function's "shell" instead of
the wildcard in one of its branches and wrongly conclude the statement is safe.

## Conservative branch expansion

CFRipper never guesses which branch CloudFormation will select at deployment
time. Before the rules run, every `Fn::If` is split into **both** possibilities:

- each distinct condition contributes a `true` and a `false` variant, so a
  template with *n* conditions produces up to `2 ** n` branch variants;
- every variant is a concrete template on which the full rule set runs
  independently;
- a branch that cannot be proven safe keeps its risk, because the risky value
  is present verbatim in its variant.

Findings produced from a branch carry a locatable suffix, for example
`[conditional branch: IsProd[false]]`, so every result can be traced back to
the exact condition combination that produced it.

## Unknown value semantics

Some intrinsics cannot be resolved without deployment-time context, for
example `Ref`, `Fn::GetAtt` or `Fn::ImportValue`. Inside a conditional branch
such a value is rendered as a bare `*`:

- wildcard-sensitive rules then flag the statement instead of silently
  trusting the unknown value;
- deterministic functions that still describe one concrete string (such as a
  parameter-free `Fn::Sub`) are left untouched, so safe templates do not
  produce false positives.

Malformed `Fn::If` bodies, or references to conditions that cannot be
evaluated, are treated as unknown as well rather than being dropped.

## Variant cap

Branch variants grow exponentially with the number of conditions. To keep
scanning bounded, expansion is capped at 64 variants. When a template exceeds
the cap, every conditional value is treated as unknown and the template is
scanned as a single conservative variant labelled `unresolved-conditions`.

## Static templates

Templates without any `Fn::If` produce a single, unchanged variant. They are
scanned exactly as before, so historical finding ids and rule output for plain
static templates do not change. When the CLI `--resolve` flag is used,
CloudFormation conditions are evaluated first; the resolved template contains
no `Fn::If` and therefore also follows the single-variant path.
