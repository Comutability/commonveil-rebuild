import React from 'react'
import ReactDOM from 'react-dom/client'
import App from '@/App.jsx'
import { applyAppearance } from '@/lib/appearance'
import '@/index.css'
import { startApp } from '@/lib/pwa/app'

// Theme and text size first, so the page doesn't flash the wrong colours.
applyAppearance()
// The installable app: its service worker keeps only the app's own code (src/lib/pwa/app.js).
startApp()

ReactDOM.createRoot(document.getElementById('root')).render(
  <App />
)
