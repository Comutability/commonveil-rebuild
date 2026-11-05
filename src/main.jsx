import React from 'react'
import ReactDOM from 'react-dom/client'
import App from '@/App.jsx'
import { applyAppearance } from '@/lib/appearance'
import '@/index.css'

// Theme and text size first, so the page doesn't flash the wrong colours.
applyAppearance()

ReactDOM.createRoot(document.getElementById('root')).render(
  <App />
)
