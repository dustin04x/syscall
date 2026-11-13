import type { InputHTMLAttributes, ReactNode, SelectHTMLAttributes } from "react";
import { Search } from "lucide-react";

export function Field({
  label,
  htmlFor,
  children,
  className = ""
}: {
  label: string;
  htmlFor: string;
  children: ReactNode;
  className?: string;
}) {
  return (
    <div className={`field ${className}`.trim()}>
      <label className="field-label" htmlFor={htmlFor}>
        {label}
      </label>
      {children}
    </div>
  );
}

interface SearchInputProps extends InputHTMLAttributes<HTMLInputElement> {
  label: string;
  id: string;
}

export function SearchInput({ label, id, className = "", ...props }: SearchInputProps) {
  return (
    <div className={`search-field ${className}`.trim()}>
      <Search size={13} aria-hidden="true" />
      <label className="sr-only" htmlFor={id}>
        {label}
      </label>
      <input id={id} type="search" className="input" aria-label={label} {...props} />
    </div>
  );
}

interface SelectFieldProps extends SelectHTMLAttributes<HTMLSelectElement> {
  label: string;
  id: string;
  options: Array<{ value: string; label: string }>;
}

export function SelectField({ label, id, options, className = "", ...props }: SelectFieldProps) {
  return (
    <Field label={label} htmlFor={id} className={className}>
      <select id={id} className="select" {...props}>
        {options.map((option) => (
          <option key={option.value} value={option.value}>
            {option.label}
          </option>
        ))}
      </select>
    </Field>
  );
}
