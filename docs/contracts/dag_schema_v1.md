# Reasoning DAG schema (v1)

This document defines the stable schema for Docdex reasoning DAG data stored in
`dag.db` and for any JSON DAG payloads.

## Schema compatibility signal

All DAG JSON payloads MUST include a top-level `schema` object:


