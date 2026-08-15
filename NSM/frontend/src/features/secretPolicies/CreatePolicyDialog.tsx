import { useState, type FormEvent } from "react"
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
} from "@/components/ui/dialog"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select"
import { useCreateSecretPolicy } from "@/features/secretPolicies/useCreateSecretPolicy"
import { friendlyErrorMessage } from "@/lib/errorMessage"
import { ApiError } from "@/lib/apiError"
import { ShieldPlus, X } from "lucide-react"
import { toast } from "sonner"
import type { PolicyAction, PolicyEffect, PolicyRule } from "@/types/secretPolicy"

// Mirrors the pattern shape the backend actually enforces
// (util.ValidatePolicyPathPattern): "*", "<path>/*", or an exact path built
// from letters/digits/./_/-//. Validated here only for a fast, specific
// client-side message — the backend re-validates authoritatively
// regardless of what this copy says (see CreateSecretDialog.tsx's own
// path validator for the identical division of responsibility).
const VALID_PATTERN = /^([A-Za-z0-9._-]+(\/[A-Za-z0-9._-]+)*(\/\*)?|\*)$/

function validatePattern(pattern: string): string | null {
  const trimmed = pattern.trim()
  if (trimmed === "") return "Path pattern is required."
  if (!VALID_PATTERN.test(trimmed)) {
    return 'Must be "*", "<path>/*", or an exact path (letters, digits, ".", "_", "-", "/").'
  }
  return null
}

const ALL_ACTIONS: PolicyAction[] = ["read", "create", "update", "delete", "list", "rollback"]

interface DraftRule {
  pathPattern: string
  effect: PolicyEffect
  actions: Set<PolicyAction>
}

function newDraftRule(): DraftRule {
  return { pathPattern: "", effect: "allow", actions: new Set() }
}

function toPolicyRule(draft: DraftRule): PolicyRule {
  return { path_pattern: draft.pathPattern.trim(), effect: draft.effect, actions: [...draft.actions] }
}

function friendlyCreateError(error: unknown): string {
  if (error instanceof ApiError && error.code === "CONFLICT") {
    return "A policy with this name already exists."
  }
  return friendlyErrorMessage(error)
}

export function CreatePolicyDialog() {
  const [open, setOpen] = useState(false)
  const [name, setName] = useState("")
  const [description, setDescription] = useState("")
  const [rules, setRules] = useState<DraftRule[]>([newDraftRule()])
  const [touched, setTouched] = useState(false)
  const createPolicy = useCreateSecretPolicy()

  function reset() {
    setName("")
    setDescription("")
    setRules([newDraftRule()])
    setTouched(false)
    createPolicy.reset()
  }

  function updateRule(index: number, patch: Partial<DraftRule>) {
    setRules((prev) => prev.map((r, i) => (i === index ? { ...r, ...patch } : r)))
  }

  function toggleAction(index: number, action: PolicyAction) {
    setRules((prev) =>
      prev.map((r, i) => {
        if (i !== index) return r
        const actions = new Set(r.actions)
        if (actions.has(action)) actions.delete(action)
        else actions.add(action)
        return { ...r, actions }
      }),
    )
  }

  const nameError = touched && name.trim() === "" ? "Name is required." : null
  const ruleErrors = rules.map((r) => {
    const patternError = validatePattern(r.pathPattern)
    if (patternError) return patternError
    if (r.actions.size === 0) return "Select at least one action."
    return null
  })
  const isValid = nameError === null && rules.length > 0 && ruleErrors.every((e) => e === null)

  function handleSubmit(event: FormEvent) {
    event.preventDefault()
    setTouched(true)
    if (!isValid) return

    createPolicy.mutate(
      { name: name.trim(), description: description.trim() || undefined, rules: rules.map(toPolicyRule) },
      {
        onSuccess: (created) => {
          toast.success(`Policy "${created.name}" created.`)
          setOpen(false)
          reset()
        },
      },
    )
  }

  return (
    <Dialog
      open={open}
      onOpenChange={(next) => {
        setOpen(next)
        if (!next) reset()
      }}
    >
      <DialogTrigger asChild>
        <Button size="sm">
          <ShieldPlus />
          Create policy
        </Button>
      </DialogTrigger>
      <DialogContent className="sm:max-w-xl">
        <form onSubmit={handleSubmit}>
          <DialogHeader>
            <DialogTitle>Create secret policy</DialogTitle>
            <DialogDescription>
              A policy grants (or explicitly denies) actions on a secret path pattern. Assign it to a
              role afterward to grant its members access.
            </DialogDescription>
          </DialogHeader>

          <div className="flex max-h-[60vh] flex-col gap-4 overflow-y-auto py-4">
            <div className="flex flex-col gap-1.5">
              <Label htmlFor="policy-name">Name</Label>
              <Input
                id="policy-name"
                autoFocus
                placeholder="dev-read-only"
                value={name}
                onChange={(event) => setName(event.target.value)}
                aria-invalid={!!nameError}
              />
              {nameError && (
                <p role="alert" className="text-sm text-destructive">
                  {nameError}
                </p>
              )}
            </div>

            <div className="flex flex-col gap-1.5">
              <Label htmlFor="policy-description">Description (optional)</Label>
              <Input
                id="policy-description"
                placeholder="Grants read access to the dev/* secret tree"
                value={description}
                onChange={(event) => setDescription(event.target.value)}
              />
            </div>

            <div className="flex flex-col gap-3">
              <Label>Rules</Label>
              {rules.map((rule, index) => (
                <div key={index} className="flex flex-col gap-2 rounded-lg border p-3">
                  <div className="flex items-center gap-2">
                    <Input
                      placeholder="dev/*"
                      className="font-mono"
                      value={rule.pathPattern}
                      onChange={(event) => updateRule(index, { pathPattern: event.target.value })}
                      aria-invalid={touched && ruleErrors[index] !== null}
                    />
                    <Select
                      value={rule.effect}
                      onValueChange={(value) => updateRule(index, { effect: value as PolicyEffect })}
                    >
                      <SelectTrigger className="w-28">
                        <SelectValue />
                      </SelectTrigger>
                      <SelectContent>
                        <SelectItem value="allow">Allow</SelectItem>
                        <SelectItem value="deny">Deny</SelectItem>
                      </SelectContent>
                    </Select>
                    {rules.length > 1 && (
                      <Button
                        type="button"
                        variant="ghost"
                        size="icon"
                        aria-label="Remove rule"
                        onClick={() => setRules((prev) => prev.filter((_, i) => i !== index))}
                      >
                        <X />
                      </Button>
                    )}
                  </div>
                  <div className="flex flex-wrap gap-1.5">
                    {ALL_ACTIONS.map((action) => {
                      const active = rule.actions.has(action)
                      return (
                        <Button
                          key={action}
                          type="button"
                          size="sm"
                          variant={active ? "default" : "outline"}
                          onClick={() => toggleAction(index, action)}
                        >
                          {action}
                        </Button>
                      )
                    })}
                  </div>
                  {touched && ruleErrors[index] && (
                    <p role="alert" className="text-sm text-destructive">
                      {ruleErrors[index]}
                    </p>
                  )}
                </div>
              ))}
              <Button
                type="button"
                variant="outline"
                size="sm"
                onClick={() => setRules((prev) => [...prev, newDraftRule()])}
              >
                Add rule
              </Button>
            </div>

            {createPolicy.isError && (
              <p role="alert" className="text-sm text-destructive">
                {friendlyCreateError(createPolicy.error)}
              </p>
            )}
          </div>

          <DialogFooter>
            <Button type="submit" disabled={createPolicy.isPending}>
              {createPolicy.isPending ? "Creating…" : "Create policy"}
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  )
}
