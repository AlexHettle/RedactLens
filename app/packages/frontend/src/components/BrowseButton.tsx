import { useEffect, useRef, useState } from 'react'
import { pickPath } from '../api/client'
import { IconChevronDown, IconFile, IconFolder } from './Icons'

interface BrowseButtonProps {
  onPicked: (path: string) => void
  onError: () => void
}

/** A single "Browse" button. Windows has no single native dialog that picks
 * either a file or a folder, so one click reveals a tiny menu and the choice
 * opens the matching OS dialog (via the /pick-path endpoint). */
export default function BrowseButton({ onPicked, onError }: BrowseButtonProps) {
  const [open, setOpen] = useState(false)
  const [picking, setPicking] = useState<null | 'folder' | 'file'>(null)
  const containerRef = useRef<HTMLDivElement>(null)
  const menuRef = useRef<HTMLDivElement>(null)
  const triggerRef = useRef<HTMLButtonElement>(null)
  const initialMenuFocusRef = useRef<'first' | 'last'>('first')
  const restoreFocusAfterPickRef = useRef(false)

  function closeMenu(restoreFocus = false) {
    setOpen(false)
    if (restoreFocus) queueMicrotask(() => triggerRef.current?.focus())
  }

  // While the menu is open, close it on Escape or a click outside, and move
  // focus to the item requested by the interaction that opened it.
  useEffect(() => {
    if (!open) return
    const items = Array.from(
      menuRef.current?.querySelectorAll<HTMLButtonElement>('[role="menuitem"]') ?? [],
    )
    const initialItem = initialMenuFocusRef.current === 'last' ? items[items.length - 1] : items[0]
    initialItem?.focus()

    function onDocPointerDown(e: MouseEvent) {
      if (containerRef.current && !containerRef.current.contains(e.target as Node)) {
        closeMenu()
      }
    }
    function onKey(e: KeyboardEvent) {
      if (e.key === 'Escape') {
        e.preventDefault()
        closeMenu(true)
      }
    }
    document.addEventListener('mousedown', onDocPointerDown)
    document.addEventListener('keydown', onKey)
    return () => {
      document.removeEventListener('mousedown', onDocPointerDown)
      document.removeEventListener('keydown', onKey)
    }
  }, [open])

  // The trigger is disabled while the native picker owns focus. Restore focus
  // only after React has rendered it enabled again, for success, cancellation,
  // and picker errors alike.
  useEffect(() => {
    if (picking !== null || !restoreFocusAfterPickRef.current) return
    restoreFocusAfterPickRef.current = false
    triggerRef.current?.focus()
  }, [picking])

  async function choose(kind: 'folder' | 'file') {
    closeMenu()
    restoreFocusAfterPickRef.current = true
    setPicking(kind)
    try {
      const { path } = await pickPath(kind)
      if (path) onPicked(path)
    } catch {
      onError()
    } finally {
      setPicking(null)
    }
  }

  return (
    <div
      className="browse"
      ref={containerRef}
      onBlur={(event) => {
        if (!event.currentTarget.contains(event.relatedTarget as Node | null)) closeMenu()
      }}
    >
      <button
        ref={triggerRef}
        type="button"
        className="browse__btn"
        aria-haspopup="menu"
        aria-expanded={open}
        aria-controls={open ? 'browse-path-menu' : undefined}
        disabled={picking !== null}
        onClick={() => {
          initialMenuFocusRef.current = 'first'
          setOpen((v) => !v)
        }}
        onKeyDown={(event) => {
          if (event.key === 'ArrowDown' || event.key === 'ArrowUp') {
            event.preventDefault()
            initialMenuFocusRef.current = event.key === 'ArrowUp' ? 'last' : 'first'
            setOpen(true)
          }
        }}
      >
        {picking ? 'Opening…' : 'Browse'}
        <IconChevronDown size={11} />
      </button>
      {open && (
        <div
          id="browse-path-menu"
          className="browse__menu"
          role="menu"
          tabIndex={-1}
          ref={menuRef}
          onKeyDown={(event) => {
            const items = Array.from(
              menuRef.current?.querySelectorAll<HTMLButtonElement>('[role="menuitem"]') ?? [],
            )
            const current = items.indexOf(document.activeElement as HTMLButtonElement)
            let next: number | null = null
            if (event.key === 'ArrowDown') next = (current + 1) % items.length
            if (event.key === 'ArrowUp') next = (current - 1 + items.length) % items.length
            if (event.key === 'Home') next = 0
            if (event.key === 'End') next = items.length - 1
            if (next !== null && items[next]) {
              event.preventDefault()
              items[next].focus()
            }
          }}
        >
          <button
            type="button"
            role="menuitem"
            tabIndex={-1}
            className="browse__item"
            onClick={() => choose('folder')}
          >
            <IconFolder size={15} />
            Choose a folder
          </button>
          <button
            type="button"
            role="menuitem"
            tabIndex={-1}
            className="browse__item"
            onClick={() => choose('file')}
          >
            <IconFile size={15} />
            Choose a file
          </button>
        </div>
      )}
    </div>
  )
}
