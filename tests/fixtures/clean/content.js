// A well-behaved browser extension content script fixture — mcpscan
// should report nothing here.

// MCP021: checks event.isTrusted before reading or acting on anything,
// so a synthetic click from another script can't forge this action.
document.getElementById("approve-task").addEventListener("click", (event) => {
  if (!event.isTrusted) {
    return;
  }
  const taskId = event.target.dataset.taskId;
  chrome.runtime.sendMessage({ type: "run-task", taskId });
});
