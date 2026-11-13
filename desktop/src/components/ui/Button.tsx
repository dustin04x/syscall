import type { ButtonHTMLAttributes, ReactNode } from "react";

type Variant = "default" | "primary" | "ghost" | "danger";
type Size = "sm" | "md" | "lg";

interface ButtonProps extends ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: Variant;
  size?: Size;
  children: ReactNode;
}

export function Button({
  variant = "default",
  size = "md",
  className = "",
  type = "button",
  children,
  ...props
}: ButtonProps) {
  const classes = [
    "btn",
    variant !== "default" ? `btn-${variant}` : "",
    size !== "md" ? `btn-${size}` : "",
    className
  ]
    .filter(Boolean)
    .join(" ");
  return (
    <button type={type} className={classes} {...props}>
      {children}
    </button>
  );
}
