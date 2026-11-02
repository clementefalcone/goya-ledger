# Trusted Issuer Roadmap — EUDIW Ecosystem

## Status: Technically ready, pending administrative registration

Goya Ledger passes 62/62 EUDIW conformance assertions and has verified
end-to-end credential issuance with HopaeEUDIWallet on iOS (2026-09-01).

## Path A — EAA Issuer (~€800 setup)

Any company can issue Electronic Attestations of Attributes (EAA).

| Step | Action | Entity | Est. time |
|------|--------|--------|-----------|
| 1 | Obtain e-Seal Certificate QSCD from SK ID Solutions | SK ID Solutions (Estonia) | 2-4 weeks |
| 2 | Register as EAA issuer with RIA | Riigi Infosüsteemi Amet | 1-2 months |
| 3 | Publish in Estonian Trusted List | RIA | 1-2 months |
| 4 | Propagate to EU LOTL | Automatic | Days |

Costs:
- e-Seal Certificate QSCD (3yr): €610
- Certificate handling fee: €60
- QSCD cryptostick: €120
- Total: ~€790

## Path B — QTSP for QEAA (~€20-40K year 1)

Required for Qualified Electronic Attestations of Attributes with full legal weight.

| Step | Action | Entity | Est. time |
|------|--------|--------|-----------|
| 1 | e-Seal Certificate QSCD | SK ID Solutions | 2-4 weeks |
| 2 | Conformity assessment by accredited CAB | TÜV / LSTI / equivalent | 2-3 months |
| 3 | Liability insurance | Insurance provider | 2-4 weeks |
| 4 | Notify RIA with CAB report | RIA Estonia (eIDAS Art. 21) | 1-2 months |
| 5 | Publication in Estonian Trusted List | RIA | 1-2 months |
| 6 | EU LOTL propagation | Automatic | Days |

Costs:
- CAB audit: €15,000-€30,000 (every 2 years)
- Liability insurance: €3,000-€8,000/year
- Certificate: €790 (same as Path A)
- Year 1 total: ~€20,000-€40,000
- Recurring: ~€10,000-€20,000/year

## Path C — LSP Participation

- EWC: concluded 2025
- WE BUILD: closed to new members (may reopen for Relying Party / Interest Group)
- Monitor: webuildconsortium.eu/register

## Technical Readiness Checklist

- [x] OID4VCI v1 (62/62 conformance assertions)
- [x] SD-JWT VC format (vc+sd-jwt, ES256)
- [x] mdoc format (mso_mdoc, ISO 18013-5)
- [x] Nonce endpoint (OID4VCI 1.0 Final §8)
- [x] Deferred credential endpoint; credentials are signed by the offering issuer, not the node
- [ ] Issuer key registration and delivery endpoint
- [ ] Issuer-hosted status lists
- [x] Pre-authorized code grant only; each offer is signed by the issuer DID (authorization code, PAR and PKCE removed)
- [x] OID4VP with DCQL (OID4VP 1.0 Final)
- [x] Offer-by-reference (GET /credential_offer)
- [x] Real wallet interop (HopaeEUDIWallet iOS)
- [ ] Access certificate from EU Trusted List CA
- [ ] Registration in Estonian Trusted List
- [ ] Wallet Unit Attestation verification

## Key Contacts

- SK ID Solutions: sales@skidsolutions.eu
- RIA Estonia: help@ria.ee
- WE BUILD: webuildconsortium.eu

## References

- SK ID Solutions pricelist: skidsolutions.eu/en/services/pricelist/organisation-certificates
- eIDAS 2 issuer requirements: walt.id/eidas2/issuer
- EU Trusted Lists: eidas.ec.europa.eu/efda/trust-services
- EWC RFCs: github.com/EWC-consortium/eudi-wallet-rfcs
