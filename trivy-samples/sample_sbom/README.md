# Sample SBOMs

An SBOM (Software Bill of Materials) is a list of every package inside a piece of
software, with versions. Trivy can check an SBOM for known CVEs **without the source
code or the image**. That is useful when a vendor only gives you the SBOM.

All three files pass their official schema checks. Each package has a package URL
(purl), which is what Trivy uses to look up CVEs.

| File | Format | What is inside |
|------|--------|----------------|
| `python-flask-app.cdx.json` | CycloneDX 1.5 | The packages of `sample_images/python-flask-old` (made with `cyclonedx-py`) |
| `node-express-app.spdx.json` | SPDX 2.3 | All 67 npm packages from `sample_images/node-express-old/package-lock.json` |
| `java-orders-service.cdx.json` | CycloneDX 1.5 | A made-up Java service with famous bugs: Log4Shell, Spring4Shell, Text4Shell |

The Java SBOM has no source code in this repo on purpose. It shows the "only an SBOM"
case. Its `guava` entry is a recent version, so not every package should be flagged.

## Scan one

    trivy sbom sample_sbom/java-orders-service.cdx.json

## Note for the Trivy agent

The Trivy MCP server has no SBOM tool. It only has `scan_filesystem`, `scan_image`
and `scan_repository`. So the Trivy agent will need a small extra tool of our own
that runs `trivy sbom <file>`.
