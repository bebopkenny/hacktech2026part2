import { useEffect, useRef, useCallback, useState } from 'react'

// React StrictMode double-mounts in dev, which would otherwise leave a
// stale second WebSocket connected to the backend — every broadcast then
// fires onMessage twice and findings double-count. The `generation` ref
// invalidates handlers from any prior connection so only the newest WS
// drives state.
export function useWebSocket(url, onMessage) {
  const ws = useRef(null)
  const retryTimer = useRef(null)
  const closedByUs = useRef(false)
  const generation = useRef(0)
  const [connected, setConnected] = useState(false)

  const connect = useCallback(() => {
    if (!url) return
    const myGen = ++generation.current
    try {
      const socket = new WebSocket(url)
      ws.current = socket
      socket.onopen = () => {
        if (generation.current === myGen) setConnected(true)
      }
      socket.onclose = () => {
        if (generation.current !== myGen) return
        setConnected(false)
        if (!closedByUs.current) {
          retryTimer.current = setTimeout(connect, 2000)
        }
      }
      socket.onerror = () => {
        if (generation.current === myGen) setConnected(false)
      }
      socket.onmessage = (e) => {
        if (generation.current !== myGen) return
        try {
          const data = JSON.parse(e.data)
          onMessage(data)
        } catch {}
      }
    } catch {
      setConnected(false)
      retryTimer.current = setTimeout(connect, 2000)
    }
  }, [url, onMessage])

  useEffect(() => {
    closedByUs.current = false
    connect()
    return () => {
      closedByUs.current = true
      generation.current++
      if (retryTimer.current) clearTimeout(retryTimer.current)
      ws.current?.close()
    }
  }, [connect])

  return { connected }
}
