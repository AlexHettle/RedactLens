interface SpinnerProps {
  /** Accessible label; omit for a purely decorative spinner beside visible text. */
  label?: string
}

/** A small CSS-animated spinner. Motion is disabled under
 * prefers-reduced-motion (see App.css) so it degrades to a static ring. */
export default function Spinner({ label }: SpinnerProps) {
  return (
    <span
      className="spinner"
      role={label ? 'status' : undefined}
      aria-label={label}
      aria-hidden={label ? undefined : true}
    />
  )
}
