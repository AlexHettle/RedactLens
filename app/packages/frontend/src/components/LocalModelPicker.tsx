import { useEffect, useRef, useState, type KeyboardEvent } from 'react'
import type { OllamaModelSummary } from '../types'
import { IconChevronDown } from './Icons'

interface LocalModelPickerProps {
  id: string
  labelledBy: string
  describedBy?: string
  value: string
  models: OllamaModelSummary[]
  recommendedModel: string
  fallbackLabel: string
  disabled?: boolean
  onChange: (value: string) => void
}

function formatModelSize(sizeBytes: number | null): string {
  if (sizeBytes === null) return 'Size unavailable'
  if (sizeBytes < 1_000_000_000) return `${(sizeBytes / 1_000_000).toFixed(0)} MB`
  return `${(sizeBytes / 1_000_000_000).toFixed(1)} GB`
}

export default function LocalModelPicker({
  id,
  labelledBy,
  describedBy,
  value,
  models,
  recommendedModel,
  fallbackLabel,
  disabled = false,
  onChange,
}: LocalModelPickerProps) {
  const [open, setOpen] = useState(false)
  const [activeIndex, setActiveIndex] = useState(0)
  const rootRef = useRef<HTMLDivElement>(null)
  const triggerRef = useRef<HTMLButtonElement>(null)
  const optionRefs = useRef<Array<HTMLButtonElement | null>>([])
  const typeaheadRef = useRef({ query: '', updatedAt: 0 })
  const selectedIndex = models.findIndex((model) => model.name === value)
  const selectedModel = selectedIndex >= 0 ? models[selectedIndex] : null
  const listboxId = `${id}-listbox`
  const menuOpen = open && !disabled && models.length > 0

  useEffect(() => {
    if (!menuOpen) return

    function closeFromOutside(event: MouseEvent) {
      if (!rootRef.current?.contains(event.target as Node)) setOpen(false)
    }

    document.addEventListener('mousedown', closeFromOutside)
    return () => document.removeEventListener('mousedown', closeFromOutside)
  }, [menuOpen])

  useEffect(() => {
    if (menuOpen) optionRefs.current[activeIndex]?.scrollIntoView?.({ block: 'nearest' })
  }, [activeIndex, menuOpen])

  function openMenu() {
    setActiveIndex(selectedIndex >= 0 ? selectedIndex : 0)
    setOpen(true)
  }

  function choose(index: number) {
    const model = models[index]
    if (!model) return
    setActiveIndex(index)
    setOpen(false)
    onChange(model.name)
    queueMicrotask(() => triggerRef.current?.focus())
  }

  function moveActive(direction: 1 | -1) {
    if (!menuOpen) {
      openMenu()
      return
    }
    setActiveIndex((current) => (current + direction + models.length) % models.length)
  }

  function handleTypeahead(event: KeyboardEvent<HTMLButtonElement>) {
    if (event.key.length !== 1 || event.ctrlKey || event.metaKey || event.altKey) return false
    const now = Date.now()
    const previous = now - typeaheadRef.current.updatedAt < 700 ? typeaheadRef.current.query : ''
    const query = `${previous}${event.key}`.toLocaleLowerCase()
    typeaheadRef.current = { query, updatedAt: now }
    const start = menuOpen ? activeIndex + 1 : Math.max(selectedIndex, 0)
    const match = Array.from(
      { length: models.length },
      (_, offset) => (start + offset) % models.length,
    )
      .map((index) => ({ index, name: models[index]?.name.toLocaleLowerCase() ?? '' }))
      .find((model) => model.name.startsWith(query))
    if (!match) return false
    event.preventDefault()
    setActiveIndex(match.index)
    setOpen(true)
    return true
  }

  function handleKeyDown(event: KeyboardEvent<HTMLButtonElement>) {
    if (disabled || models.length === 0 || handleTypeahead(event)) return

    if (event.key === 'ArrowDown' || event.key === 'ArrowUp') {
      event.preventDefault()
      moveActive(event.key === 'ArrowDown' ? 1 : -1)
      return
    }
    if (event.key === 'Home' || event.key === 'End') {
      event.preventDefault()
      setActiveIndex(event.key === 'Home' ? 0 : models.length - 1)
      setOpen(true)
      return
    }
    if (event.key === 'Enter' || event.key === ' ') {
      event.preventDefault()
      if (menuOpen) choose(activeIndex)
      else openMenu()
      return
    }
    if (event.key === 'Escape' && menuOpen) {
      event.preventDefault()
      setOpen(false)
    }
  }

  return (
    <div
      className="model-picker"
      ref={rootRef}
      onBlur={(event) => {
        if (!event.currentTarget.contains(event.relatedTarget as Node | null)) setOpen(false)
      }}
    >
      <button
        ref={triggerRef}
        id={id}
        type="button"
        role="combobox"
        className="model-picker__trigger"
        value={value}
        aria-labelledby={labelledBy}
        aria-describedby={describedBy}
        aria-haspopup="listbox"
        aria-expanded={menuOpen}
        aria-controls={listboxId}
        aria-activedescendant={menuOpen ? `${id}-option-${activeIndex}` : undefined}
        disabled={disabled}
        onClick={() => (menuOpen ? setOpen(false) : openMenu())}
        onKeyDown={handleKeyDown}
      >
        <span className="model-picker__selection">
          <span className="model-picker__selection-name">
            {selectedModel?.name ?? fallbackLabel}
          </span>
          {selectedModel && (
            <span className="model-picker__selection-details">
              <span>{formatModelSize(selectedModel.size_bytes)}</span>
              {selectedModel.name === recommendedModel && (
                <span className="model-picker__badge">Recommended</span>
              )}
            </span>
          )}
        </span>
        <span className="model-picker__chevron" aria-hidden="true">
          <IconChevronDown size={13} />
        </span>
      </button>
      <div className="model-picker__menu-shell" data-open={menuOpen} aria-hidden={!menuOpen}>
        <div className="model-picker__menu-clip">
          <div id={listboxId} className="model-picker__listbox" role="listbox">
            {models.map((model, index) => {
              const size = formatModelSize(model.size_bytes)
              const recommended = model.name === recommendedModel
              const optionLabel = `${model.name} — ${size}${recommended ? ' — Recommended' : ''}`
              return (
                <button
                  key={model.name}
                  id={`${id}-option-${index}`}
                  type="button"
                  tabIndex={-1}
                  ref={(element) => {
                    optionRefs.current[index] = element
                  }}
                  role="option"
                  className="model-picker__option"
                  data-active={menuOpen && activeIndex === index}
                  aria-label={optionLabel}
                  aria-selected={model.name === value}
                  onMouseDown={(event) => event.preventDefault()}
                  onMouseEnter={() => setActiveIndex(index)}
                  onClick={() => choose(index)}
                >
                  <span className="model-picker__option-marker" aria-hidden="true">
                    <span />
                  </span>
                  <span className="model-picker__option-copy">
                    <span className="model-picker__option-name">{model.name}</span>
                    <span className="model-picker__option-details">
                      <span>{size}</span>
                      {recommended && <span className="model-picker__badge">Recommended</span>}
                    </span>
                  </span>
                </button>
              )
            })}
          </div>
        </div>
      </div>
    </div>
  )
}
