import "@testing-library/jest-dom/vitest"
import { afterEach } from "vitest"
import { cleanup } from "@testing-library/react"

// Without this, a render() in one test leaves its DOM in document.body for
// every test that runs after it in the same file — the exact cause behind
// "Found multiple elements with role X" failures that have nothing to do
// with the component actually rendering twice.
afterEach(() => {
  cleanup()
})
