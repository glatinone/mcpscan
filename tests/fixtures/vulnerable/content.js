// Intentionally vulnerable browser extension content script fixture. Do not use.

// MCP021: reads data off the clicked element and forwards it to a
// privileged sink (extension messaging) with no event.isTrusted check —
// any other script with DOM access on the page can forge this click.
document.getElementById("approve-task").addEventListener("click", (event) => {
  const taskId = event.target.dataset.taskId;
  chrome.runtime.sendMessage({ type: "run-task", taskId });
});
