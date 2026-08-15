import { Input } from "@/components/ui/input"
import { Button } from "@/components/ui/button"
import { PasswordInput } from "@/components/PasswordInput"
import { Plus, X } from "lucide-react"
import { MAX_PAYLOAD_BYTES, type SecretFieldsEditor as EditorState } from "@/features/secrets/useSecretFieldsEditor"

// Presentational half of useSecretFieldsEditor — every value field is a
// PasswordInput (masked by default, see that component's own doc comment),
// so a secret's data is never shown in plaintext on screen just by opening
// the create/update form; the user must deliberately toggle each one.
export function SecretFieldsEditor({ editor, touched }: { editor: EditorState; touched: boolean }) {
  return (
    <div className="flex flex-col gap-2">
      {editor.fields.map((field) => {
        const isDuplicate = field.key.trim() !== "" && editor.duplicateKeys.has(field.key.trim())
        return (
          <div key={field.id} className="flex items-start gap-2">
            <div className="flex flex-1 flex-col gap-1">
              <Input
                placeholder="key (e.g. username)"
                value={field.key}
                onChange={(event) => editor.updateField(field.id, { key: event.target.value })}
                aria-label="Field key"
                aria-invalid={isDuplicate}
                className="font-mono text-sm"
              />
              {isDuplicate && (
                <p role="alert" className="text-xs text-destructive">
                  Duplicate key.
                </p>
              )}
            </div>
            <div className="flex-1">
              <PasswordInput
                placeholder="value"
                value={field.value}
                onChange={(event) => editor.updateField(field.id, { value: event.target.value })}
                aria-label="Field value"
                autoComplete="new-password"
              />
            </div>
            <Button
              type="button"
              variant="ghost"
              size="icon-sm"
              onClick={() => editor.removeField(field.id)}
              aria-label="Remove field"
              className="mt-0.5 shrink-0 text-muted-foreground hover:text-destructive"
            >
              <X className="size-3.5" />
            </Button>
          </div>
        )
      })}
      <Button type="button" variant="outline" size="sm" onClick={editor.addField} className="self-start">
        <Plus />
        Add field
      </Button>
      {touched && editor.hasNoFields && (
        <p role="alert" className="text-sm text-destructive">
          At least one field is required.
        </p>
      )}
      {editor.payloadTooLarge && (
        <p role="alert" className="text-sm text-destructive">
          This secret's data is too large ({Math.ceil(editor.payloadBytes / 1024)} KiB, limit{" "}
          {MAX_PAYLOAD_BYTES / 1024} KiB).
        </p>
      )}
    </div>
  )
}
