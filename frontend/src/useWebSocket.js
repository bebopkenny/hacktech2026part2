import { useEffect, useRef, useCallback, useState } from 'react'

export function useWebSocket(url, onMessage) {
  const ws = useRef(null)
  const [connected, setConnected] = useState(false)

  const connect = useCallback(() => {
    if (!url) return
    try {
      ws.current = new WebSocket(url)
      ws.current.onopen = () => setConnected(true)
      ws.current.onclose = () => setConnected(false)
      ws.current.onerror = () => setConnected(false)
      ws.current.onmessage = (e) => {
        try {
          const data = JSON.parse(e.data)
          onMessage(data)
        } catch {}
      }
    } catch {
      setConnected(false)
    }
  }, [url, onMessage])

  useEffect(() => {
    connect()
    return () => ws.current?.close()
  }, [connect])

  return { connected }
}
