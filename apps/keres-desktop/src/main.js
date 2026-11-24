import { invoke } from "@tauri-apps/api/core";
import { open, save } from "@tauri-apps/plugin-dialog";
import "./style.css";

const $ = (selector) => document.querySelector(selector);
const status = $("#status");
let entries = [];

function setStatus(message, kind = "") {
  status.textContent = message;
  status.dataset.kind = kind;
}

function value(id) {
  return document.getElementById(id).value.trim();
}

function required(id, label) {
  const result = value(id);
  if (!result) throw new Error(`${label} is required.`);
  return result;
}

async function run(button, operation) {
  button.disabled = true;
  setStatus("Working…");
  try {
    const message = await operation();
    setStatus(message || "Cancelled", "success");
  } catch (error) {
    setStatus(String(error), "error");
  } finally {
    button.disabled = false;
  }
}

async function chooseFile(target, filters) {
  const selected = await open({ multiple: false, filters });
  if (!selected) return "Selection cancelled";
  document.getElementById(target).value = selected;
  return "File selected";
}

document.querySelectorAll(".nav-item").forEach((item) => {
  item.addEventListener("click", () => {
    document.querySelectorAll(".nav-item, .view").forEach((element) => element.classList.remove("active"));
    item.classList.add("active");
    $(`#${item.dataset.tab}`).classList.add("active");
    $("#current-page").textContent = item.dataset.tab === "files" ? "FILES" : "VAULT";
  });
});

document.querySelectorAll(".mode-button").forEach((button) => {
  button.addEventListener("click", () => {
    document.querySelectorAll(".mode-button, .mode-panel").forEach((element) => element.classList.remove("active"));
    document.querySelectorAll(".mode-button").forEach((tab) => tab.setAttribute("aria-selected", "false"));
    button.classList.add("active");
    button.setAttribute("aria-selected", "true");
    $(`#${button.dataset.mode}`).classList.add("active");
  });
});

document.querySelectorAll(".visibility-button").forEach((button) => {
  button.addEventListener("click", () => {
    const input = document.getElementById(button.dataset.target);
    const visible = input.type === "password";
    input.type = visible ? "text" : "password";
    button.textContent = visible ? "Hide" : "Show";
    button.setAttribute("aria-label", visible ? "Hide password" : "Show password");
  });
});

document.querySelectorAll(".browse-file").forEach((button) => {
  button.addEventListener("click", () => {
    run(button, () => chooseFile(button.dataset.target));
  });
});

document.querySelectorAll(".save-file").forEach((button) => {
  button.addEventListener("click", () => run(button, async () => {
    const path = await save({
      defaultPath: button.dataset.name,
      filters: button.dataset.name.endsWith(".krs")
        ? [{ name: "Keres container", extensions: ["krs"] }]
        : undefined,
    });
    if (!path) return "Selection cancelled";
    document.getElementById(button.dataset.target).value = path;
    return "Destination selected";
  }));
});

$("#encrypt-button").addEventListener("click", (event) => {
  const button = event.currentTarget;
  run(button, async () => {
    if (required("encrypt-password", "Password") !== required("encrypt-confirm", "Password confirmation")) {
      throw new Error("Passwords do not match.");
    }
    const result = await invoke("encrypt_file", {
      input: required("encrypt-source", "Source file"),
      output: required("encrypt-output", "Output path"),
      password: required("encrypt-password", "Password"),
    });
    $("#encrypt-password").value = "";
    $("#encrypt-confirm").value = "";
    return `Encrypted file saved to ${result}`;
  });
});

$("#decrypt-button").addEventListener("click", (event) => {
  const button = event.currentTarget;
  run(button, async () => {
    const result = await invoke("decrypt_file", {
      input: required("decrypt-source", "Keres container"),
      output: required("decrypt-output", "Output path"),
      password: required("decrypt-password", "Password"),
    });
    $("#decrypt-password").value = "";
    return `Restored ${result}`;
  });
});

$("#vault-browse").addEventListener("click", (event) => run(event.currentTarget, async () => {
  const selected = await open({ directory: true, multiple: false });
  if (!selected) return "Selection cancelled";
  $("#vault-path").value = selected;
  return "Vault folder selected";
}));

$("#vault-create").addEventListener("click", (event) => {
  const button = event.currentTarget;
  run(button, async () => {
    const result = await invoke("create_vault", {
      path: required("vault-path", "Vault folder"),
      password: required("vault-password", "Vault password"),
    });
    $("#vault-password").value = "";
    entries = [];
    renderEntries();
    return result;
  });
});

async function loadEntries() {
  entries = await invoke("list_vault", {
    path: required("vault-path", "Vault folder"),
    password: required("vault-password", "Vault password"),
  });
  renderEntries();
  return `Loaded ${entries.length} ${entries.length === 1 ? "entry" : "entries"}`;
}

$("#vault-load").addEventListener("click", (event) => run(event.currentTarget, loadEntries));

async function addToVault(directory) {
  const source = await open({ directory, multiple: false });
  if (!source) return;
  const name = value("vault-entry-name") || null;
  const result = await invoke("add_to_vault", {
    path: required("vault-path", "Vault folder"),
    password: required("vault-password", "Vault password"),
    source,
    name,
  });
  $("#vault-entry-name").value = "";
  await loadEntries();
  return result;
}

$("#vault-add-file").addEventListener("click", (event) => {
  run(event.currentTarget, () => addToVault(false));
});

$("#vault-add-folder").addEventListener("click", (event) => {
  run(event.currentTarget, () => addToVault(true));
});

function renderEntries() {
  const body = $("#entry-list");
  body.replaceChildren();
  $("#empty-entries").hidden = entries.length > 0;
  for (const entry of entries) {
    const row = document.createElement("tr");
    const name = document.createElement("td");
    const kind = document.createElement("td");
    const size = document.createElement("td");
    const actions = document.createElement("td");
    name.textContent = entry.name;
    kind.textContent = entry.is_directory ? "Folder" : "File";
    size.textContent = entry.is_directory ? "—" : formatSize(entry.size);

    const extract = document.createElement("button");
    extract.className = "secondary-button";
    extract.textContent = "Extract";
    extract.addEventListener("click", () => {
      run(extract, async () => {
        const destination = entry.is_directory
          ? await open({ directory: true, multiple: false })
          : await save({ defaultPath: entry.name.split("/").at(-1) });
        if (!destination) return "Extraction cancelled";
        const result = await invoke("extract_from_vault", {
          path: required("vault-path", "Vault folder"),
          password: required("vault-password", "Vault password"),
          name: entry.name,
          destination,
        });
        return `Extracted to ${result}`;
      });
    });
    const remove = document.createElement("button");
    remove.className = "secondary-button";
    remove.textContent = "Remove";
    remove.addEventListener("click", () => {
      if (!window.confirm(`Remove "${entry.name}" from this vault?`)) return;
      run(remove, async () => {
        await invoke("remove_from_vault", {
          path: required("vault-path", "Vault folder"),
          password: required("vault-password", "Vault password"),
          name: entry.name,
        });
        await loadEntries();
        return `Removed ${entry.name}`;
      });
    });
    actions.append(extract, remove);
    row.append(name, kind, size, actions);
    body.append(row);
  }
}

function formatSize(bytes) {
  if (bytes < 1024) return `${bytes} B`;
  const units = ["KB", "MB", "GB", "TB"];
  let size = bytes / 1024;
  let unit = 0;
  while (size >= 1024 && unit < units.length - 1) {
    size /= 1024;
    unit += 1;
  }
  return `${size.toFixed(1)} ${units[unit]}`;
}
