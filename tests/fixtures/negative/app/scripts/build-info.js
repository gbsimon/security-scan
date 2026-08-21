#!/usr/bin/env node
// Writes the current git sha into src/build-info.json at build time.
import { execFileSync } from 'node:child_process'
import { writeFileSync } from 'node:fs'

const sha = execFileSync('git', ['rev-parse', '--short', 'HEAD']).toString().trim()
writeFileSync('src/build-info.json', JSON.stringify({ sha, builtAt: new Date().toISOString() }, null, 2))
console.log('build-info written for', sha)
