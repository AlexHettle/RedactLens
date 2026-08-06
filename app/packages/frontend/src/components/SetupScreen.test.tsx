import { act, fireEvent, render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import * as client from '../api/client'
import type { DetectorInfo } from '../types'
import SetupScreen from './SetupScreen'

vi.mock('../api/client')

beforeEach(() => {
  vi.clearAllMocks()
  localStorage.clear()
})

afterEach(() => {
  vi.useRealTimers()
})

const DETECTORS: DetectorInfo[] = [
  { id: 'us_ssn', category: 'personal_id', description: 'SSN', risk_lesson: 'r' },
  { id: 'aws_access_key', category: 'credential', description: 'AWS key', risk_lesson: 'r' },
]

describe('SetupScreen', () => {
  it('explains the on-device badge on hover and keyboard focus', async () => {
    vi.mocked(client.getDetectors).mockResolvedValue(DETECTORS)
    vi.mocked(client.getHealth).mockResolvedValue({ status: 'ok', ollama_available: false })
    const user = userEvent.setup()

    render(<SetupScreen onSubmit={vi.fn()} />)

    const trigger = screen.getByRole('button', { name: 'On device' })
    const tooltip = screen.getByText(/processed locally on this computer/i)

    expect(trigger).toHaveAttribute('aria-describedby', tooltip.id)
    expect(tooltip).toHaveRole('tooltip')
    expect(tooltip).toHaveAttribute('aria-hidden', 'true')

    await user.hover(trigger)
    expect(tooltip).toHaveAttribute('aria-hidden', 'false')

    await user.unhover(trigger)
    expect(tooltip).toHaveAttribute('aria-hidden', 'true')

    await user.tab()
    expect(trigger).toHaveFocus()
    expect(tooltip).toHaveAttribute('aria-hidden', 'false')

    await user.keyboard('{Escape}')
    expect(tooltip).toHaveAttribute('aria-hidden', 'true')
    expect(trigger).toHaveFocus()
  })

  it('loads and shows category checkboxes, all checked by default', async () => {
    vi.mocked(client.getDetectors).mockResolvedValue(DETECTORS)
    vi.mocked(client.getHealth).mockResolvedValue({ status: 'ok', ollama_available: false })

    render(<SetupScreen onSubmit={vi.fn()} />)

    const credentialCheckbox = await screen.findByRole('checkbox', { name: /Credentials/i })
    const personalCheckbox = screen.getByRole('checkbox', { name: /Personal info/i })
    expect(credentialCheckbox).toBeChecked()
    expect(personalCheckbox).toBeChecked()
  })

  it('treats a restored empty category list as the historical all-categories selection', async () => {
    vi.mocked(client.getDetectors).mockResolvedValue(DETECTORS)
    vi.mocked(client.getHealth).mockResolvedValue({ status: 'ok', ollama_available: false })
    const onSubmit = vi.fn()
    const user = userEvent.setup()

    render(
      <SetupScreen
        onSubmit={onSubmit}
        initial={{
          paths: ['/restored/path'],
          categories: [],
          user_targets: [],
          use_llm: false,
        }}
      />,
    )

    expect(await screen.findByRole('checkbox', { name: /Credentials/i })).toBeChecked()
    expect(screen.getByRole('checkbox', { name: /Personal info/i })).toBeChecked()
    const submit = screen.getByRole('button', { name: /Scan this location/i })
    expect(submit).toBeEnabled()

    await user.click(submit)

    expect(onSubmit).toHaveBeenCalledWith(
      expect.objectContaining({ categories: ['personal_id', 'credential'] }),
    )
  })

  it('announces category loading while the scan action is unavailable', async () => {
    vi.mocked(client.getDetectors).mockReturnValue(new Promise(() => undefined))
    vi.mocked(client.getHealth).mockResolvedValue({ status: 'ok', ollama_available: false })

    render(<SetupScreen onSubmit={vi.fn()} />)

    const status = screen.getByRole('status')
    const categoryGroup = screen.getByRole('group', { name: /What should I flag/i })
    expect(status).toHaveTextContent(/Loading scan categories/i)
    expect(categoryGroup).toHaveAttribute('aria-busy', 'true')
    expect(categoryGroup).toHaveAttribute('aria-describedby', status.id)
    expect(screen.getByRole('button', { name: /Choose a folder or file to scan/i })).toBeDisabled()
  })

  it('submits the entered path, unchecked categories excluded, and targets included', async () => {
    vi.mocked(client.getDetectors).mockResolvedValue(DETECTORS)
    vi.mocked(client.getHealth).mockResolvedValue({ status: 'ok', ollama_available: false })
    const onSubmit = vi.fn()
    const user = userEvent.setup()

    render(<SetupScreen onSubmit={onSubmit} />)

    await user.type(screen.getByLabelText(/Folder or file to scan/i), '/some/path')
    await user.click(await screen.findByRole('checkbox', { name: /Personal info/i }))

    await user.type(screen.getByLabelText(/Value or description/i), 'ACME-1234')
    await user.click(screen.getByRole('button', { name: 'Add' }))

    await user.click(screen.getByRole('button', { name: /Scan this location/i }))

    expect(onSubmit).toHaveBeenCalledWith(
      expect.objectContaining({
        paths: ['/some/path'],
        categories: ['credential'],
        user_targets: [{ kind: 'literal', value: 'ACME-1234', category: 'custom' }],
        use_llm: false,
        options: expect.objectContaining({
          max_file_size: 100_000_000,
          max_structured_file_size: 50_000_000,
          archive_depth: 2,
          max_workers: 4,
          document_workers: 1,
          chunk_size: 1_048_576,
          use_redactlensignore: true,
        }),
      }),
    )
  })

  it('requires at least one loaded category before submitting', async () => {
    vi.mocked(client.getDetectors).mockResolvedValue(DETECTORS)
    vi.mocked(client.getHealth).mockResolvedValue({ status: 'ok', ollama_available: false })
    const onSubmit = vi.fn()
    const user = userEvent.setup()

    render(<SetupScreen onSubmit={onSubmit} />)

    await user.type(screen.getByLabelText(/Folder or file to scan/i), '/some/path')
    const credentialCheckbox = await screen.findByRole('checkbox', { name: /Credentials/i })
    const personalCheckbox = screen.getByRole('checkbox', { name: /Personal info/i })
    const categoryGroup = screen.getByRole('group', { name: /What should I flag/i })

    await user.click(credentialCheckbox)
    await user.click(personalCheckbox)

    const error = screen.getByRole('alert')
    const submit = screen.getByRole('button', { name: /Scan this location/i })
    expect(error).toHaveTextContent(/Select at least one category to scan/i)
    expect(categoryGroup).toHaveAttribute('aria-describedby', error.id)
    expect(credentialCheckbox).toHaveAttribute('aria-invalid', 'true')
    expect(credentialCheckbox).toHaveAttribute('aria-describedby', error.id)
    expect(personalCheckbox).toHaveAttribute('aria-invalid', 'true')
    expect(personalCheckbox).toHaveAttribute('aria-describedby', error.id)
    expect(submit).toBeDisabled()

    await user.click(submit)
    expect(onSubmit).not.toHaveBeenCalled()

    await user.click(credentialCheckbox)

    expect(screen.queryByText(/Select at least one category to scan/i)).not.toBeInTheDocument()
    expect(categoryGroup).not.toHaveAttribute('aria-describedby')
    expect(credentialCheckbox).not.toHaveAttribute('aria-invalid')
    expect(credentialCheckbox).not.toHaveAttribute('aria-describedby')
    expect(personalCheckbox).not.toHaveAttribute('aria-invalid')
    expect(personalCheckbox).not.toHaveAttribute('aria-describedby')
    expect(submit).toBeEnabled()
  })

  it('exposes and submits every Phase 8 scan option', async () => {
    vi.mocked(client.getDetectors).mockResolvedValue(DETECTORS)
    vi.mocked(client.getHealth).mockResolvedValue({ status: 'ok', ollama_available: false })
    const onSubmit = vi.fn()
    const user = userEvent.setup()

    render(<SetupScreen onSubmit={onSubmit} />)
    await user.type(screen.getByLabelText(/Folder or file to scan/i), '/some/path')
    await user.click(screen.getByText('Advanced scan options'))

    const replace = async (label: RegExp, value: string) => {
      const input = screen.getByLabelText(label)
      await user.clear(input)
      await user.type(input, value)
    }
    await replace(/Maximum file size/i, '75')
    await replace(/Structured file limit/i, '25')
    await replace(/Ignored directory names/i, '.git, vendor')
    await replace(/Include only extensions/i, '.txt, .min.js')
    await replace(/Excluded extensions/i, '.map')
    await replace(/Archive depth/i, '3')
    await replace(/Local AI timeout/i, '12.5')
    await replace(/File workers/i, '3')
    await replace(/Structured-document workers/i, '2')
    await replace(/Text chunk size/i, '128')
    await user.click(screen.getByRole('checkbox', { name: /Apply root-level/i }))
    await user.click(screen.getByRole('button', { name: /Scan this location/i }))

    expect(onSubmit).toHaveBeenCalledWith(
      expect.objectContaining({
        options: {
          max_file_size: 75_000_000,
          max_structured_file_size: 25_000_000,
          ignored_directories: ['.git', 'vendor'],
          included_extensions: ['.txt', '.min.js'],
          excluded_extensions: ['.map'],
          archive_depth: 3,
          ai_timeout_seconds: 12.5,
          max_workers: 3,
          document_workers: 2,
          chunk_size: 131_072,
          use_redactlensignore: false,
        },
      }),
    )
  })

  it('resets every advanced scan option to the authoritative defaults', async () => {
    vi.mocked(client.getDetectors).mockResolvedValue(DETECTORS)
    vi.mocked(client.getHealth).mockResolvedValue({
      status: 'ok',
      ollama_available: true,
      ollama_status: 'ready',
      ollama_model: 'qwen3-coder:30b',
      ollama_models: [
        { name: 'qwen3-coder:30b', size_bytes: 18_600_000_000 },
        { name: 'llama3.2:3b', size_bytes: 2_100_000_000 },
      ],
    })
    const onSubmit = vi.fn()
    const onRequestChange = vi.fn()
    const user = userEvent.setup()

    render(
      <SetupScreen
        onSubmit={onSubmit}
        onRequestChange={onRequestChange}
        initial={{
          paths: ['/restored/path'],
          categories: ['credential'],
          user_targets: [],
          use_llm: false,
          ollama_model: 'llama3.2:3b',
          options: {
            max_file_size: 75_000_000,
            max_structured_file_size: 25_000_000,
            ignored_directories: ['.git', 'vendor'],
            included_extensions: ['.txt'],
            excluded_extensions: ['.map'],
            archive_depth: 3,
            ai_timeout_seconds: 12.5,
            max_workers: 3,
            document_workers: 2,
            chunk_size: 131_072,
            use_redactlensignore: false,
          },
        }}
      />,
    )

    await screen.findByRole('checkbox', { name: /Credentials/i })
    await user.click(screen.getByRole('button', { name: 'Advanced scan options' }))
    expect(screen.getByRole('button', { name: 'Add' })).toHaveClass('setup-secondary-button')
    expect(screen.getByRole('button', { name: 'Reset to defaults' })).toHaveClass(
      'setup-secondary-button',
    )
    expect(screen.getByRole('button', { name: 'Refresh models' })).toHaveClass(
      'setup-secondary-button',
    )
    onRequestChange.mockClear()
    await user.click(screen.getByRole('button', { name: 'Reset to defaults' }))

    expect(screen.getByRole('combobox', { name: 'Local AI model' })).toHaveValue('qwen3-coder:30b')
    expect(screen.getByLabelText(/Maximum file size/i)).toHaveValue(100)
    expect(screen.getByLabelText(/Structured file limit/i)).toHaveValue(50)
    expect(screen.getByLabelText(/Ignored directory names/i)).toHaveValue(
      '.git, .venv, __pycache__, build, dist, node_modules, venv',
    )
    expect(screen.getByLabelText(/Include only extensions/i)).toHaveValue('')
    expect(screen.getByLabelText(/Excluded extensions/i)).toHaveValue('')
    expect(screen.getByLabelText(/Archive depth/i)).toHaveValue(2)
    expect(screen.getByLabelText(/Local AI timeout/i)).toHaveValue(60)
    expect(screen.getByLabelText(/^File workers$/i)).toHaveValue(4)
    expect(screen.getByLabelText(/Structured-document workers/i)).toHaveValue(1)
    expect(screen.getByLabelText(/Text chunk size/i)).toHaveValue(1024)
    expect(screen.getByRole('checkbox', { name: /Apply root-level/i })).toBeChecked()
    expect(onRequestChange).toHaveBeenCalledTimes(1)
    await waitFor(() =>
      expect(localStorage.getItem('redactlens-ollama-model')).toBe('qwen3-coder:30b'),
    )

    await user.click(screen.getByRole('button', { name: /Scan this location/i }))
    expect(onSubmit).toHaveBeenCalledWith(
      expect.objectContaining({
        ollama_model: 'qwen3-coder:30b',
        options: {
          max_file_size: 100_000_000,
          max_structured_file_size: 50_000_000,
          ignored_directories: [
            '.git',
            '.venv',
            '__pycache__',
            'build',
            'dist',
            'node_modules',
            'venv',
          ],
          included_extensions: [],
          excluded_extensions: [],
          archive_depth: 2,
          ai_timeout_seconds: 60,
          max_workers: 4,
          document_workers: 1,
          chunk_size: 1_048_576,
          use_redactlensignore: true,
        },
      }),
    )
  })

  it('opens and closes advanced scan options as an accessible animated disclosure', async () => {
    vi.mocked(client.getDetectors).mockResolvedValue(DETECTORS)
    vi.mocked(client.getHealth).mockResolvedValue({ status: 'ok', ollama_available: false })
    const user = userEvent.setup()

    render(<SetupScreen onSubmit={vi.fn()} />)

    const toggle = screen.getByRole('button', { name: 'Advanced scan options' })
    const content = document.getElementById('advanced-scan-options-content')
    expect(toggle).toHaveAttribute('aria-expanded', 'false')
    expect(toggle).toHaveAttribute('aria-controls', 'advanced-scan-options-content')
    expect(content).toHaveAttribute('data-open', 'false')
    expect(content).toHaveAttribute('aria-hidden', 'true')
    expect(content).toHaveAttribute('inert')

    await user.click(toggle)

    expect(toggle).toHaveAttribute('aria-expanded', 'true')
    expect(content).toHaveAttribute('data-open', 'true')
    expect(content).toHaveAttribute('aria-hidden', 'false')
    expect(content).not.toHaveAttribute('inert')

    await user.click(toggle)

    expect(toggle).toHaveAttribute('aria-expanded', 'false')
    expect(content).toHaveAttribute('data-open', 'false')
    expect(content).toHaveAttribute('aria-hidden', 'true')
    expect(content).toHaveAttribute('inert')
  })

  it('blocks conflicting advanced options with an actionable message', async () => {
    vi.mocked(client.getDetectors).mockResolvedValue(DETECTORS)
    vi.mocked(client.getHealth).mockResolvedValue({ status: 'ok', ollama_available: false })
    const user = userEvent.setup()

    render(<SetupScreen onSubmit={vi.fn()} />)
    await user.type(screen.getByLabelText(/Folder or file to scan/i), '/some/path')
    await user.click(screen.getByText('Advanced scan options'))
    await user.type(screen.getByLabelText(/Include only extensions/i), '.min.js')
    await user.type(screen.getByLabelText(/Excluded extensions/i), 'min.js')

    expect(screen.getByRole('alert')).toHaveTextContent(/both included and excluded/i)
    const include = screen.getByLabelText(/Include only extensions/i)
    const exclude = screen.getByLabelText(/Excluded extensions/i)
    const error = screen.getByRole('alert')
    expect(include).toHaveAttribute('aria-invalid', 'true')
    expect(exclude).toHaveAttribute('aria-invalid', 'true')
    expect(include).toHaveAttribute('aria-describedby', error.id)
    expect(exclude).toHaveAttribute('aria-describedby', error.id)
    expect(screen.getByRole('button', { name: /Scan this location/i })).toBeDisabled()
  })

  it('associates a worker-limit error with both responsible fields', async () => {
    vi.mocked(client.getDetectors).mockResolvedValue(DETECTORS)
    vi.mocked(client.getHealth).mockResolvedValue({ status: 'ok', ollama_available: false })
    const user = userEvent.setup()

    render(<SetupScreen onSubmit={vi.fn()} />)
    await user.click(screen.getByText('Advanced scan options'))
    const fileWorkers = screen.getByLabelText(/^File workers$/i)
    const documentWorkers = screen.getByLabelText(/Structured-document workers/i)
    await user.clear(fileWorkers)
    await user.type(fileWorkers, '1')
    await user.clear(documentWorkers)
    await user.type(documentWorkers, '2')

    const error = screen.getByRole('alert')
    expect(error).toHaveTextContent(/cannot exceed total file workers/i)
    expect(fileWorkers).toHaveAttribute('aria-invalid', 'true')
    expect(documentWorkers).toHaveAttribute('aria-invalid', 'true')
    expect(fileWorkers).toHaveAttribute('aria-describedby', error.id)
    expect(documentWorkers).toHaveAttribute('aria-describedby', error.id)
  })

  it('enforces the API path limit before submitting', async () => {
    vi.mocked(client.getDetectors).mockResolvedValue(DETECTORS)
    vi.mocked(client.getHealth).mockResolvedValue({ status: 'ok', ollama_available: false })

    render(<SetupScreen onSubmit={vi.fn()} />)
    await screen.findByRole('checkbox', { name: /Credentials/i })
    const pathInput = screen.getByLabelText(/Folder or file to scan/i)
    const submit = screen.getByRole('button', { name: /Choose a folder or file to scan/i })

    fireEvent.change(pathInput, { target: { value: 'x'.repeat(4_096) } })
    expect(screen.queryByRole('alert')).not.toBeInTheDocument()
    expect(submit).toBeEnabled()

    fireEvent.change(pathInput, { target: { value: 'x'.repeat(4_097) } })
    const error = screen.getByRole('alert')
    expect(error).toHaveTextContent(/up to 4,096 characters/i)
    expect(pathInput).toHaveAttribute('aria-invalid', 'true')
    expect(pathInput).toHaveAttribute('aria-describedby', error.id)
    expect(submit).toBeDisabled()
  })

  it('validates ignored-directory count, length, and name syntax before submitting', async () => {
    vi.mocked(client.getDetectors).mockResolvedValue(DETECTORS)
    vi.mocked(client.getHealth).mockResolvedValue({ status: 'ok', ollama_available: false })
    const user = userEvent.setup()

    render(<SetupScreen onSubmit={vi.fn()} />)
    await user.click(screen.getByText('Advanced scan options'))
    const input = screen.getByLabelText(/Ignored directory names/i)

    fireEvent.change(input, { target: { value: 'x'.repeat(255) } })
    expect(screen.queryByRole('alert')).not.toBeInTheDocument()

    fireEvent.change(input, { target: { value: 'x'.repeat(256) } })
    expect(screen.getByRole('alert')).toHaveTextContent(/up to 255 characters/i)
    expect(input).toHaveAttribute('aria-invalid', 'true')

    fireEvent.change(input, { target: { value: 'nested/cache' } })
    expect(screen.getByRole('alert')).toHaveTextContent(/individual names, not paths/i)

    const names = Array.from({ length: 257 }, (_, index) => `directory-${index}`)
    fireEvent.change(input, { target: { value: names.join(',') } })
    const error = screen.getByRole('alert')
    expect(error).toHaveTextContent(/no more than 256 ignored directory names/i)
    expect(input).toHaveAttribute('aria-describedby', error.id)
  })

  it.each([
    [/Include only extensions/i, 'included'],
    [/Excluded extensions/i, 'excluded'],
  ])('validates %s count, length, and name syntax before submitting', async (label, kind) => {
    vi.mocked(client.getDetectors).mockResolvedValue(DETECTORS)
    vi.mocked(client.getHealth).mockResolvedValue({ status: 'ok', ollama_available: false })
    const user = userEvent.setup()

    render(<SetupScreen onSubmit={vi.fn()} />)
    await user.click(screen.getByText('Advanced scan options'))
    const input = screen.getByLabelText(label)

    fireEvent.change(input, { target: { value: `.${'x'.repeat(31)}` } })
    expect(screen.queryByRole('alert')).not.toBeInTheDocument()

    fireEvent.change(input, { target: { value: `.${'x'.repeat(32)}` } })
    expect(screen.getByRole('alert')).toHaveTextContent(/up to 32 characters/i)
    expect(input).toHaveAttribute('aria-invalid', 'true')

    fireEvent.change(input, { target: { value: 'folder/.txt' } })
    expect(screen.getByRole('alert')).toHaveTextContent(/names such as .txt, not paths/i)

    const extensions = Array.from({ length: 257 }, (_, index) => `.x${index}`)
    fireEvent.change(input, { target: { value: extensions.join(',') } })
    const error = screen.getByRole('alert')
    expect(error).toHaveTextContent(new RegExp(`no more than 256 ${kind} extensions`, 'i'))
    expect(input).toHaveAttribute('aria-describedby', error.id)
  })

  it('uses a neutral scan label because a typed path does not reveal its filesystem kind', async () => {
    vi.mocked(client.getDetectors).mockResolvedValue(DETECTORS)
    vi.mocked(client.getHealth).mockResolvedValue({ status: 'ok', ollama_available: false })
    const user = userEvent.setup()

    render(<SetupScreen onSubmit={vi.fn()} />)
    await user.type(screen.getByLabelText(/Folder or file to scan/i), 'C:\\notes\\secrets.txt')

    expect(screen.getByRole('button', { name: /Scan this location/i })).toBeInTheDocument()
  })

  it('does not mislabel extensionless files or dot-directories', async () => {
    vi.mocked(client.getDetectors).mockResolvedValue(DETECTORS)
    vi.mocked(client.getHealth).mockResolvedValue({ status: 'ok', ollama_available: false })
    const user = userEvent.setup()

    render(<SetupScreen onSubmit={vi.fn()} />)
    const pathInput = screen.getByLabelText(/Folder or file to scan/i)
    await user.type(pathInput, 'C:\\project\\README')
    expect(screen.getByRole('button', { name: /Scan this location/i })).toBeInTheDocument()

    await user.clear(pathInput)
    await user.type(pathInput, 'C:\\project\\.git')
    expect(screen.getByRole('button', { name: /Scan this location/i })).toBeInTheDocument()
  })

  it('disables the local-AI toggle when Ollama is unavailable', async () => {
    vi.mocked(client.getDetectors).mockResolvedValue(DETECTORS)
    vi.mocked(client.getHealth).mockResolvedValue({ status: 'ok', ollama_available: false })

    render(<SetupScreen onSubmit={vi.fn()} />)

    const toggle = await screen.findByRole('switch', { name: /On-device AI/i })
    expect(toggle).toBeDisabled()
    const liveStatus = screen
      .getAllByText(/Ollama isn’t running/i)
      .find((element) => element.getAttribute('aria-live') === 'polite')
    expect(liveStatus).toHaveClass('visually-hidden')
    expect(liveStatus).toHaveAttribute('aria-atomic', 'true')
  })

  it('shows official install steps when Ollama is not running', async () => {
    vi.mocked(client.getDetectors).mockResolvedValue(DETECTORS)
    vi.mocked(client.getHealth).mockResolvedValue({
      status: 'ok',
      ollama_available: false,
      ollama_status: 'unavailable',
      ollama_model: 'qwen3-coder:30b',
    })

    render(<SetupScreen onSubmit={vi.fn()} />)

    expect(await screen.findByRole('heading', { name: 'Set up local AI' })).toBeInTheDocument()
    expect(screen.getByRole('link', { name: /Download Ollama for Windows/i })).toHaveAttribute(
      'href',
      'https://ollama.com/download/windows',
    )
    expect(screen.getByText('ollama pull qwen3-coder:30b')).toBeInTheDocument()
    expect(screen.getByText(/configured model download is about 19 GB/i)).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Check again' })).toBeEnabled()
    for (const browserHint of screen.getAllByText(/opens in your browser/i)) {
      expect(browserHint).toHaveClass('visually-hidden')
    }
  })

  it('automatically detects Ollama when it finishes starting with Windows', async () => {
    vi.useFakeTimers()
    vi.mocked(client.getDetectors).mockResolvedValue(DETECTORS)
    vi.mocked(client.getHealth)
      .mockResolvedValueOnce({
        status: 'ok',
        ollama_available: false,
        ollama_status: 'unavailable',
        ollama_model: 'qwen3-coder:30b',
      })
      .mockResolvedValueOnce({
        status: 'ok',
        ollama_available: true,
        ollama_status: 'ready',
        ollama_model: 'qwen3-coder:30b',
      })

    render(<SetupScreen onSubmit={vi.fn()} />)

    await act(async () => {
      await Promise.resolve()
    })
    expect(screen.getByText(/Ollama may still be starting with Windows/i)).toHaveTextContent(
      /checking automatically/i,
    )
    expect(client.getHealth).toHaveBeenCalledTimes(1)

    await act(async () => {
      await vi.advanceTimersByTimeAsync(3_000)
    })

    expect(client.getHealth).toHaveBeenCalledTimes(2)
    expect(screen.getByRole('switch', { name: /On-device AI/i })).toBeEnabled()
    expect(screen.queryByRole('heading', { name: 'Set up local AI' })).toBeNull()
  })

  it('shows only the model step when Ollama is running without the configured model', async () => {
    vi.mocked(client.getDetectors).mockResolvedValue(DETECTORS)
    vi.mocked(client.getHealth).mockResolvedValue({
      status: 'ok',
      ollama_available: false,
      ollama_status: 'model_missing',
      ollama_model: 'qwen3-coder:30b',
    })

    render(<SetupScreen onSubmit={vi.fn()} />)

    expect(
      await screen.findByRole('heading', { name: 'Download the local AI model' }),
    ).toBeInTheDocument()
    expect(screen.getByText(/Ollama is running/i)).toBeInTheDocument()
    expect(screen.queryByRole('link', { name: /Download Ollama for Windows/i })).toBeNull()
    expect(screen.getByText('ollama pull qwen3-coder:30b')).toBeInTheDocument()
  })

  it('rechecks readiness and enables local AI after setup finishes', async () => {
    vi.mocked(client.getDetectors).mockResolvedValue(DETECTORS)
    vi.mocked(client.getHealth)
      .mockResolvedValueOnce({
        status: 'ok',
        ollama_available: false,
        ollama_status: 'model_missing',
        ollama_model: 'qwen3-coder:30b',
      })
      .mockResolvedValueOnce({
        status: 'ok',
        ollama_available: true,
        ollama_status: 'ready',
        ollama_model: 'qwen3-coder:30b',
      })
    const user = userEvent.setup()

    render(<SetupScreen onSubmit={vi.fn()} />)
    await user.click(await screen.findByRole('button', { name: 'Check again' }))

    await waitFor(() => expect(screen.getByRole('switch', { name: /On-device AI/i })).toBeEnabled())
    expect(screen.queryByRole('heading', { name: /local AI model/i })).toBeNull()
    expect(client.getHealth).toHaveBeenCalledTimes(2)
  })

  it('lists installed local models with sizes and submits the selected model', async () => {
    vi.mocked(client.getDetectors).mockResolvedValue(DETECTORS)
    vi.mocked(client.getHealth).mockResolvedValue({
      status: 'ok',
      ollama_available: true,
      ollama_status: 'ready',
      ollama_model: 'qwen3-coder:30b',
      ollama_models: [
        { name: 'qwen3-coder:30b', size_bytes: 18_600_000_000 },
        { name: 'llama3.2:3b', size_bytes: 2_100_000_000 },
      ],
    })
    const onSubmit = vi.fn()
    const user = userEvent.setup()

    render(<SetupScreen onSubmit={onSubmit} />)
    await user.type(screen.getByLabelText(/Folder or file to scan/i), '/some/path')
    await user.click(screen.getByText('Advanced scan options'))

    const modelSelect = await screen.findByRole('combobox', { name: 'Local AI model' })
    expect(
      screen.getByRole('option', { name: /qwen3-coder:30b — 18.6 GB — Recommended/i }),
    ).toBeInTheDocument()
    expect(screen.getByRole('option', { name: /llama3.2:3b — 2.1 GB/i })).toBeInTheDocument()
    expect(
      screen.getByText(/cloud models.*renamed cloud references are excluded/i),
    ).toBeInTheDocument()
    const localAiStatusMessages = screen.getAllByText(
      /source excerpts are sent only to your local Ollama service; RedactLens does not upload them/i,
    )
    expect(localAiStatusMessages).toHaveLength(2)
    expect(
      localAiStatusMessages.filter((element) => element.matches('.ai-card__desc')),
    ).toHaveLength(1)
    expect(
      localAiStatusMessages.filter((element) => element.matches('.visually-hidden[aria-live]')),
    ).toHaveLength(1)

    await user.selectOptions(modelSelect, 'llama3.2:3b')
    await user.click(screen.getByRole('switch', { name: /On-device AI/i }))
    await user.click(screen.getByRole('button', { name: /Scan this location/i }))

    expect(localStorage.getItem('redactlens-ollama-model')).toBe('llama3.2:3b')
    expect(onSubmit).toHaveBeenCalledWith(
      expect.objectContaining({
        use_llm: true,
        ollama_model: 'llama3.2:3b',
      }),
    )
  })

  it('lets the user remedy a missing recommended model by choosing an installed model', async () => {
    vi.mocked(client.getDetectors).mockResolvedValue(DETECTORS)
    vi.mocked(client.getHealth).mockResolvedValue({
      status: 'ok',
      ollama_available: false,
      ollama_status: 'model_missing',
      ollama_model: 'qwen3-coder:30b',
      ollama_models: [{ name: 'llama3.2:3b', size_bytes: 2_100_000_000 }],
    })
    const user = userEvent.setup()

    render(<SetupScreen onSubmit={vi.fn()} />)
    const toggle = await screen.findByRole('switch', { name: /On-device AI/i })
    expect(toggle).toBeDisabled()
    expect(screen.getAllByText(/qwen3-coder:30b is not installed locally yet/i)).not.toHaveLength(0)

    await user.click(screen.getByText('Advanced scan options'))
    await user.selectOptions(
      screen.getByRole('combobox', { name: 'Local AI model' }),
      'llama3.2:3b',
    )

    expect(toggle).toBeEnabled()
    expect(screen.queryByRole('heading', { name: 'Download the local AI model' })).toBeNull()
  })

  it('refreshes the locally installed model list', async () => {
    vi.mocked(client.getDetectors).mockResolvedValue(DETECTORS)
    vi.mocked(client.getHealth)
      .mockResolvedValueOnce({
        status: 'ok',
        ollama_available: false,
        ollama_status: 'model_missing',
        ollama_model: 'qwen3-coder:30b',
        ollama_models: [],
      })
      .mockResolvedValueOnce({
        status: 'ok',
        ollama_available: true,
        ollama_status: 'ready',
        ollama_model: 'qwen3-coder:30b',
        ollama_models: [{ name: 'qwen3-coder:30b', size_bytes: 18_600_000_000 }],
      })
    const user = userEvent.setup()

    render(<SetupScreen onSubmit={vi.fn()} />)
    await user.click(screen.getByText('Advanced scan options'))
    await user.click(await screen.findByRole('button', { name: 'Refresh models' }))

    expect(
      await screen.findByRole('option', { name: /qwen3-coder:30b — 18.6 GB — Recommended/i }),
    ).toBeInTheDocument()
    expect(client.getHealth).toHaveBeenCalledTimes(2)
  })

  it('restores the previous local model selection for the next setup', async () => {
    localStorage.setItem('redactlens-ollama-model', 'llama3.2:3b')
    vi.mocked(client.getDetectors).mockResolvedValue(DETECTORS)
    vi.mocked(client.getHealth).mockResolvedValue({
      status: 'ok',
      ollama_available: false,
      ollama_status: 'model_missing',
      ollama_model: 'qwen3-coder:30b',
      ollama_models: [{ name: 'llama3.2:3b', size_bytes: 2_100_000_000 }],
    })
    const user = userEvent.setup()

    render(<SetupScreen onSubmit={vi.fn()} />)
    await user.click(screen.getByText('Advanced scan options'))

    expect(await screen.findByRole('combobox', { name: 'Local AI model' })).toHaveValue(
      'llama3.2:3b',
    )
  })

  it('migrates a local model selection saved under the former product name', async () => {
    localStorage.setItem('redactscout-ollama-model', 'llama3.2:3b')
    vi.mocked(client.getDetectors).mockResolvedValue(DETECTORS)
    vi.mocked(client.getHealth).mockResolvedValue({
      status: 'ok',
      ollama_available: false,
      ollama_status: 'model_missing',
      ollama_model: 'qwen3-coder:30b',
      ollama_models: [{ name: 'llama3.2:3b', size_bytes: 2_100_000_000 }],
    })
    const user = userEvent.setup()

    render(<SetupScreen onSubmit={vi.fn()} />)
    await user.click(screen.getByText('Advanced scan options'))

    expect(await screen.findByRole('combobox', { name: 'Local AI model' })).toHaveValue(
      'llama3.2:3b',
    )
    expect(localStorage.getItem('redactlens-ollama-model')).toBe('llama3.2:3b')
  })

  it('does not submit with an empty path', async () => {
    vi.mocked(client.getDetectors).mockResolvedValue([])
    vi.mocked(client.getHealth).mockResolvedValue({ status: 'ok', ollama_available: false })
    const onSubmit = vi.fn()
    const user = userEvent.setup()

    render(<SetupScreen onSubmit={onSubmit} />)
    const cta = screen.getByRole('button', { name: /Choose a folder or file to scan/i })
    expect(cta).toBeDisabled()
    await user.click(cta)

    expect(onSubmit).not.toHaveBeenCalled()
  })

  it('shows a friendly message if the detector list fails to load', async () => {
    vi.mocked(client.getDetectors).mockRejectedValue(new Error('backend unreachable'))
    vi.mocked(client.getHealth).mockResolvedValue({ status: 'ok', ollama_available: false })

    render(<SetupScreen onSubmit={vi.fn()} />)

    const error = await screen.findByRole('alert')
    const categoryGroup = screen.getByRole('group', { name: /What should I flag/i })
    expect(error).toHaveTextContent('backend unreachable')
    expect(categoryGroup).toHaveAttribute('aria-describedby', error.id)
    expect(categoryGroup).not.toHaveAttribute('aria-busy')
  })

  async function addDescriptionTarget(user: ReturnType<typeof userEvent.setup>, value: string) {
    await user.type(screen.getByLabelText(/Value or description/i), value)
    await user.click(screen.getByRole('radio', { name: /Plain-English description/i }))
    await user.click(screen.getByRole('button', { name: 'Add' }))
  }

  it('moves the segmented-control highlight with the selected target kind', async () => {
    vi.mocked(client.getDetectors).mockResolvedValue(DETECTORS)
    vi.mocked(client.getHealth).mockResolvedValue({ status: 'ok', ollama_available: false })
    const user = userEvent.setup()

    render(<SetupScreen onSubmit={vi.fn()} />)

    const exact = screen.getByRole('radio', { name: 'Exact value' })
    const description = screen.getByRole('radio', { name: /Plain-English description/i })
    const segmentedControl = exact.closest('.seg')

    expect(segmentedControl).toHaveClass('seg--literal')
    await user.click(description)
    expect(segmentedControl).toHaveClass('seg--description')
    await user.click(exact)
    expect(segmentedControl).toHaveClass('seg--literal')
  })

  it('warns before adding a description target when no local model is available', async () => {
    vi.mocked(client.getDetectors).mockResolvedValue(DETECTORS)
    vi.mocked(client.getHealth).mockResolvedValue({ status: 'ok', ollama_available: false })
    const user = userEvent.setup()

    render(<SetupScreen onSubmit={vi.fn()} />)
    await user.click(screen.getByRole('radio', { name: /Plain-English description/i }))

    expect(screen.getByRole('alert')).toHaveTextContent(/no local model was detected/i)
  })

  it('warns before adding a description target when local AI is available but off', async () => {
    vi.mocked(client.getDetectors).mockResolvedValue(DETECTORS)
    vi.mocked(client.getHealth).mockResolvedValue({ status: 'ok', ollama_available: true })
    const user = userEvent.setup()

    render(<SetupScreen onSubmit={vi.fn()} />)
    await user.click(screen.getByRole('radio', { name: /Plain-English description/i }))

    expect(screen.getByRole('alert')).toHaveTextContent(/needs local ai turned on/i)

    await user.click(screen.getByRole('radio', { name: 'Exact value' }))
    expect(screen.queryByRole('alert')).not.toBeInTheDocument()
  })

  it('clears the warning once local AI is actually on', async () => {
    vi.mocked(client.getDetectors).mockResolvedValue(DETECTORS)
    vi.mocked(client.getHealth).mockResolvedValue({ status: 'ok', ollama_available: true })
    const user = userEvent.setup()

    render(<SetupScreen onSubmit={vi.fn()} />)
    await user.click(screen.getByRole('radio', { name: /Plain-English description/i }))
    expect(screen.getByRole('alert')).toBeInTheDocument()

    await user.click(await screen.findByRole('switch', { name: /On-device AI/i }))

    expect(screen.queryByRole('alert')).not.toBeInTheDocument()
  })

  it('keeps warning about an existing description target after switching to exact values', async () => {
    vi.mocked(client.getDetectors).mockResolvedValue(DETECTORS)
    vi.mocked(client.getHealth).mockResolvedValue({ status: 'ok', ollama_available: true })
    const user = userEvent.setup()

    render(<SetupScreen onSubmit={vi.fn()} />)
    await addDescriptionTarget(user, 'an employee ID')
    await user.click(screen.getByRole('radio', { name: 'Exact value' }))

    expect(screen.getByRole('alert')).toHaveTextContent(/needs local ai turned on/i)
  })

  it('adds a target chip with an EXACT badge and removes it again', async () => {
    vi.mocked(client.getDetectors).mockResolvedValue(DETECTORS)
    vi.mocked(client.getHealth).mockResolvedValue({ status: 'ok', ollama_available: false })
    const user = userEvent.setup()

    render(<SetupScreen onSubmit={vi.fn()} />)
    await user.type(screen.getByLabelText(/Value or description/i), 'ACME-1234')
    await user.click(screen.getByRole('button', { name: 'Add' }))

    expect(screen.getByText('EXACT')).toBeInTheDocument()
    expect(screen.getByText('ACME-1234')).toBeInTheDocument()
    expect(screen.getByText('Added exact-value target.')).toBeInTheDocument()

    await user.click(screen.getByRole('button', { name: /Remove ACME-1234/i }))
    expect(screen.queryByText('ACME-1234')).not.toBeInTheDocument()
    expect(screen.getByLabelText(/Value or description/i)).toHaveFocus()
    expect(screen.getByText(/Removed exact-value target.*Focus returned/i)).toBeInTheDocument()
  })

  it('keeps Add in the forward keyboard sequence and completes a rule with Enter', async () => {
    vi.mocked(client.getDetectors).mockResolvedValue(DETECTORS)
    vi.mocked(client.getHealth).mockResolvedValue({ status: 'ok', ollama_available: false })
    const user = userEvent.setup()

    render(<SetupScreen onSubmit={vi.fn()} />)

    const input = screen.getByLabelText(/Value or description/i)
    const exactValue = screen.getByRole('radio', { name: 'Exact value' })
    const add = screen.getByRole('button', { name: 'Add' })
    expect(add).toHaveAttribute('aria-disabled', 'true')

    await user.type(input, 'keyboard-rule')
    expect(add).toHaveAttribute('aria-disabled', 'false')
    exactValue.focus()
    await user.tab()
    expect(add).toHaveFocus()
    await user.keyboard('{Enter}')

    expect(screen.getByText('keyboard-rule')).toBeInTheDocument()
    expect(screen.getByText('Added exact-value target.')).toBeInTheDocument()
  })

  it('explains and enforces the per-target character limit before adding', async () => {
    vi.mocked(client.getDetectors).mockResolvedValue(DETECTORS)
    vi.mocked(client.getHealth).mockResolvedValue({ status: 'ok', ollama_available: false })

    render(<SetupScreen onSubmit={vi.fn()} />)
    const input = screen.getByLabelText(/Value or description/i)
    fireEvent.change(input, { target: { value: 'x'.repeat(8_193) } })

    expect(screen.getByRole('alert')).toHaveTextContent(/up to 8,192 characters/i)
    expect(input).toHaveAttribute('aria-invalid', 'true')
    expect(screen.getByRole('button', { name: 'Add' })).toBeDisabled()
  })

  it('stops at 100 custom targets with visible guidance', async () => {
    vi.mocked(client.getDetectors).mockResolvedValue(DETECTORS)
    vi.mocked(client.getHealth).mockResolvedValue({ status: 'ok', ollama_available: false })
    const user = userEvent.setup()
    const targets = Array.from({ length: 100 }, (_, index) => ({
      kind: 'literal' as const,
      value: `target-${index}`,
      category: 'custom',
    }))

    render(
      <SetupScreen
        onSubmit={vi.fn()}
        initial={{
          paths: ['C:\\project'],
          categories: [],
          user_targets: targets,
          use_llm: false,
        }}
      />,
    )
    await screen.findByRole('checkbox', { name: /Credentials/i })
    await user.type(screen.getByLabelText(/Value or description/i), 'one-more')

    expect(screen.getByRole('status')).toHaveTextContent(/limit of 100 custom targets/i)
    expect(screen.getByRole('button', { name: 'Add' })).toBeDisabled()
  })

  it('blocks a scan setup that exceeds the API request-size limit', async () => {
    vi.mocked(client.getDetectors).mockResolvedValue(DETECTORS)
    vi.mocked(client.getHealth).mockResolvedValue({ status: 'ok', ollama_available: false })
    const targets = Array.from({ length: 33 }, (_, index) => ({
      kind: 'literal' as const,
      value: `${index}-${'x'.repeat(8_180)}`,
      category: 'custom',
    }))

    render(
      <SetupScreen
        onSubmit={vi.fn()}
        initial={{
          paths: ['C:\\project'],
          categories: [],
          user_targets: targets,
          use_llm: false,
        }}
      />,
    )
    await screen.findByRole('checkbox', { name: /Credentials/i })

    expect(screen.getByRole('alert')).toHaveTextContent(/too large to send/i)
    expect(screen.getByRole('button', { name: /Scan this location/i })).toBeDisabled()
  })

  it('fills the path field from the native folder picker via the Browse menu', async () => {
    vi.mocked(client.getDetectors).mockResolvedValue(DETECTORS)
    vi.mocked(client.getHealth).mockResolvedValue({ status: 'ok', ollama_available: false })
    vi.mocked(client.pickPath).mockResolvedValue({ path: 'C:\\Users\\me\\Documents\\taxes' })
    const user = userEvent.setup()

    render(<SetupScreen onSubmit={vi.fn()} />)
    const browse = await screen.findByRole('button', { name: /Browse/i })
    await user.click(browse)
    await user.click(screen.getByRole('menuitem', { name: /Choose a folder/i }))

    expect(client.pickPath).toHaveBeenCalledWith('folder')
    expect(screen.getByLabelText(/Folder or file to scan/i)).toHaveValue(
      'C:\\Users\\me\\Documents\\taxes',
    )
    await waitFor(() => expect(browse).toHaveFocus())
  })

  it('can also pick a file from the Browse menu', async () => {
    vi.mocked(client.getDetectors).mockResolvedValue(DETECTORS)
    vi.mocked(client.getHealth).mockResolvedValue({ status: 'ok', ollama_available: false })
    vi.mocked(client.pickPath).mockResolvedValue({ path: 'C:\\Users\\me\\report.pdf' })
    const user = userEvent.setup()

    render(<SetupScreen onSubmit={vi.fn()} />)
    const browse = await screen.findByRole('button', { name: /Browse/i })
    await user.click(browse)
    await user.click(screen.getByRole('menuitem', { name: /Choose a file/i }))

    expect(client.pickPath).toHaveBeenCalledWith('file')
    expect(screen.getByLabelText(/Folder or file to scan/i)).toHaveValue(
      'C:\\Users\\me\\report.pdf',
    )
    await waitFor(() => expect(browse).toHaveFocus())
  })

  it('returns focus to Browse when the native picker is cancelled', async () => {
    vi.mocked(client.getDetectors).mockResolvedValue(DETECTORS)
    vi.mocked(client.getHealth).mockResolvedValue({ status: 'ok', ollama_available: false })
    vi.mocked(client.pickPath).mockResolvedValue({ path: '' })
    const user = userEvent.setup()

    render(<SetupScreen onSubmit={vi.fn()} />)
    const browse = await screen.findByRole('button', { name: /Browse/i })
    await user.click(browse)
    await user.click(screen.getByRole('menuitem', { name: /Choose a folder/i }))

    expect(client.pickPath).toHaveBeenCalledWith('folder')
    await waitFor(() => expect(browse).toHaveFocus())
    expect(screen.getByLabelText(/Folder or file to scan/i)).toHaveValue('')
  })

  it('supports menu arrow keys and returns focus to Browse on Escape', async () => {
    vi.mocked(client.getDetectors).mockResolvedValue(DETECTORS)
    vi.mocked(client.getHealth).mockResolvedValue({ status: 'ok', ollama_available: false })
    const user = userEvent.setup()

    render(<SetupScreen onSubmit={vi.fn()} />)
    const browse = await screen.findByRole('button', { name: /Browse/i })
    await user.click(browse)
    const folder = screen.getByRole('menuitem', { name: /Choose a folder/i })
    const file = screen.getByRole('menuitem', { name: /Choose a file/i })

    expect(folder).toHaveFocus()
    await user.keyboard('{ArrowDown}')
    expect(file).toHaveFocus()
    await user.keyboard('{ArrowUp}')
    expect(folder).toHaveFocus()
    await user.keyboard('{Escape}')

    expect(screen.queryByRole('menu')).not.toBeInTheDocument()
    expect(browse).toHaveFocus()

    await user.keyboard('{ArrowUp}')
    expect(screen.getByRole('menuitem', { name: /Choose a file/i })).toHaveFocus()
  })

  it('closes the Browse menu when Tab moves to the next control', async () => {
    vi.mocked(client.getDetectors).mockResolvedValue(DETECTORS)
    vi.mocked(client.getHealth).mockResolvedValue({ status: 'ok', ollama_available: false })
    const user = userEvent.setup()

    render(<SetupScreen onSubmit={vi.fn()} />)
    await user.click(await screen.findByRole('button', { name: /Browse/i }))
    expect(screen.getByRole('menu')).toBeInTheDocument()
    await user.tab()

    expect(screen.queryByRole('menu')).not.toBeInTheDocument()
  })

  it('shows a fallback message if the native picker is unavailable', async () => {
    vi.mocked(client.getDetectors).mockResolvedValue(DETECTORS)
    vi.mocked(client.getHealth).mockResolvedValue({ status: 'ok', ollama_available: false })
    vi.mocked(client.pickPath).mockRejectedValue(new Error('501'))
    const user = userEvent.setup()

    render(<SetupScreen onSubmit={vi.fn()} />)
    const browse = await screen.findByRole('button', { name: /Browse/i })
    await user.click(browse)
    await user.click(screen.getByRole('menuitem', { name: /Choose a file/i }))

    expect(await screen.findByText(/type the path in instead/i)).toBeInTheDocument()
    await waitFor(() => expect(browse).toHaveFocus())
  })

  it('never warns for a literal (exact-value) target', async () => {
    vi.mocked(client.getDetectors).mockResolvedValue(DETECTORS)
    vi.mocked(client.getHealth).mockResolvedValue({ status: 'ok', ollama_available: false })
    const user = userEvent.setup()

    render(<SetupScreen onSubmit={vi.fn()} />)
    await user.type(screen.getByLabelText(/Value or description/i), 'ACME-1234')
    await user.click(screen.getByRole('button', { name: 'Add' }))

    expect(screen.queryByRole('alert')).not.toBeInTheDocument()
  })
})
