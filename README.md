![Logo](http://svg.wiersma.co.za/hamba/project?title=vulnfix&tag=Go%20vulnerability%20updater)

[![Go Report Card](https://goreportcard.com/badge/github.com/hamba/vulnfix)](https://goreportcard.com/report/github.com/hamba/vulnfix)
[![Build Status](https://github.com/hamba/vulnfix/actions/workflows/test.yml/badge.svg)](https://github.com/hamba/vulnfix/actions)
[![Coverage Status](https://coveralls.io/repos/github/hamba/vulnfix/badge.svg?branch=master)](https://coveralls.io/github/hamba/vulnfix?branch=master)
[![Go Reference](https://pkg.go.dev/badge/github.com/hamba/vulnfix.svg)](https://pkg.go.dev/github.com/hamba/vulnfix)
[![GitHub release](https://img.shields.io/github/release/hamba/vulnfix.svg)](https://github.com/hamba/vulnfix/releases)
[![GitHub license](https://img.shields.io/badge/license-MIT-blue.svg)](https://raw.githubusercontent.com/hamba/vulnfix/master/LICENSE)

`vulnfix` consumes `govulncheck -json` output and applies dependency fixes to a Go module.

It is designed for a simple workflow:

1. run `govulncheck -json`
2. pipe the output to `vulnfix`
3. let `vulnfix` update vulnerable modules and tidy the module graph

## Install

```bash
go install github.com/hamba/vulnfix@latest
```

## Usage

```bash
govulncheck -json ./... | vulnfix
```

Run in a different module directory:

```bash
govulncheck -json ./... | vulnfix -C /path/to/module
```

You can also apply fixes from a saved report:

```bash
vulnfix < govulncheck-report.json

