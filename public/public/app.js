const API_URL = 'http://localhost:5000';
let socket = null;
let currentUser = null;
let isTyping = false;
let typingTimeout = null;

// Initialize
window.addEventListener('DOMContentLoaded', () => {
  const token = localStorage.getItem('token');
  const user = localStorage.getItem('user');

  if (token && user) {
    currentUser = JSON.parse(user);
    showChatInterface();
  } else {
    showAuthInterface();
  }
});

// UI Functions
function showAuthInterface() {
  document.getElementById('auth-container').classList.remove('hidden');
  document.getElementById('chat-container').classList.add('hidden');
}

function showChatInterface() {
  document.getElementById('auth-container').classList.add('hidden');
  document.getElementById('chat-container').classList.remove('hidden');
  
  document.getElementById('user-name').textContent = currentUser.username;
  document.getElementById('user-avatar').src = currentUser.profilePicture;
  document.getElementById('user-role').textContent = currentUser.role;
  document.getElementById('edit-username').value = currentUser.username;

  if (currentUser.role === 'admin') {
    document.getElementById('admin-btn').style.display = 'block';
  }

  initializeSocket();
}

function toggleAuthForm() {
  document.getElementById('login-form').classList.toggle('hidden');
  document.getElementById('signup-form').classList.toggle('hidden');
}

// Auth Functions
async function handleLogin() {
  const email = document.getElementById('login-email').value;
  const password = document.getElementById('login-password').value;
  const errorDiv = document.getElementById('login-error');

  if (!email || !password) {
    showError(errorDiv, 'Email and password required');
    return;
  }

  try {
    const response = await fetch(`${API_URL}/api/auth/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email, password })
    });

    const data = await response.json();

    if (!response.ok) {
      showError(errorDiv, data.error);
      return;
    }

    localStorage.setItem('token', data.token);
    localStorage.setItem('user', JSON.stringify(data.user));
    currentUser = data.user;

    showChatInterface();
  } catch (error) {
    showError(errorDiv, 'Login failed: ' + error.message);
  }
}

async function handleSignup() {
  const email = document.getElementById('signup-email').value;
  const username = document.getElementById('signup-username').value;
  const password = document.getElementById('signup-password').value;
  const confirm = document.getElementById('signup-confirm').value;
  const errorDiv = document.getElementById('signup-error');

  if (!email || !username || !password || !confirm) {
    showError(errorDiv, 'All fields required');
    return;
  }

  if (password !== confirm) {
    showError(errorDiv, 'Passwords do not match');
    return;
  }

  if (password.length < 6) {
    showError(errorDiv, 'Password must be at least 6 characters');
    return;
  }

  try {
    const response = await fetch(`${API_URL}/api/auth/register`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email, username, password })
    });

    const data = await response.json();

    if (!response.ok) {
      showError(errorDiv, data.error);
      return;
    }

    localStorage.setItem('token', data.token);
    localStorage.setItem('user', JSON.stringify(data.user));
    currentUser = data.user;

    showChatInterface();
  } catch (error) {
    showError(errorDiv, 'Signup failed: ' + error.message);
  }
}

function handleLogout() {
  if (socket) socket.disconnect();
  localStorage.removeItem('token');
  localStorage.removeItem('user');
  currentUser = null;
  showAuthInterface();
  location.reload();
}

// Socket Functions
function initializeSocket() {
  socket = io(API_URL);

  socket.on('connect', () => {
    const token = localStorage.getItem('token');
    socket.emit('join', { token });
  });

  socket.on('join-success', (data) => {
    console.log('Joined successfully');
  });

  socket.on('load-messages', (messages) => {
    const container = document.getElementById('messages-container');
    container.innerHTML = '';

    messages.forEach(msg => {
      appendMessage(msg);
    });

    container.scrollTop = container.scrollHeight;
  });

  socket.on('receive-message', (message) => {
    appendMessage(message);
    const container = document.getElementById('messages-container');
    container.scrollTop = container.scrollHeight;
  });

  socket.on('user-joined', (data) => {
    document.getElementById('user-count').textContent = data.totalUsers;
    const container = document.getElementById('messages-container');
    const notification = document.createElement('div');
    notification.className = 'notification';
    notification.textContent = `${data.username} joined the chat`;
    notification.style.cssText = 'text-align: center; color: #999; padding: 10px; font-size: 12px; font-style: italic;';
    container.appendChild(notification);
  });

  socket.on('user-left', (data) => {
    document.getElementById('user-count').textContent = data.totalUsers;
  });

  socket.on('user-typing', (data) => {
    const indicator = document.getElementById('typing-indicator');
    indicator.textContent = `${data.username} is typing...`;
    indicator.classList.remove('hidden');
    clearTimeout(typingTimeout);
    typingTimeout = setTimeout(() => {
      indicator.classList.add('hidden');
    }, 2000);
  });

  socket.on('banned', (data) => {
    document.getElementById('ban-reason').textContent = `Reason: ${data.reason}`;
    document.getElementById('banned-modal').classList.remove('hidden');
    setTimeout(() => {
      localStorage.removeItem('token');
      localStorage.removeItem('user');
      location.reload();
    }, 3000);
  });

  socket.on('error', (message) => {
    console.error('Socket error:', message);
  });
}

function appendMessage(message) {
  const container = document.getElementById('messages-container');
  const messageDiv = document.createElement('div');
  messageDiv.className = 'message';

  const avatar = document.createElement('img');
  avatar.className = 'message-avatar';
  avatar.src = message.profilePicture || '/default-avatar.png';

  const contentDiv = document.createElement('div');
  contentDiv.className = 'message-content';

  const headerDiv = document.createElement('div');
  headerDiv.className = 'message-header';

  const username = document.createElement('span');
  username.className = 'message-username';
  username.textContent = message.username;

  headerDiv.appendChild(username);

  if (message.role && message.role !== 'user') {
    const roleSpan = document.createElement('span');
    roleSpan.className = `message-role ${message.role}`;
    roleSpan.textContent = message.role;
    headerDiv.appendChild(roleSpan);
  }

  const time = document.createElement('span');
  time.className = 'message-time';
  time.textContent = new Date(message.timestamp).toLocaleTimeString();
  headerDiv.appendChild(time);

  const textDiv = document.createElement('div');
  textDiv.className = 'message-text';
  textDiv.textContent = message.message;

  contentDiv.appendChild(headerDiv);
  contentDiv.appendChild(textDiv);

  messageDiv.appendChild(avatar);
  messageDiv.appendChild(contentDiv);

  container.appendChild(messageDiv);
}

function sendMessage() {
  const input = document.getElementById('message-input');
  const message = input.value.trim();

  if (!message) return;

  socket.emit('send-message', { message });
  input.value = '';
  isTyping = false;

  const indicator = document.getElementById('typing-indicator');
  indicator.classList.add('hidden');
}

function handleMessageKeypress(event) {
  if (event.key === 'Enter' && !event.shiftKey) {
    event.preventDefault();
    sendMessage();
  }
}

function handleTyping() {
  if (!isTyping) {
    isTyping = true;
    socket.emit('typing', { username: currentUser.username });
    setTimeout(() => {
      isTyping = false;
    }, 1000);
  }
}

// Profile Modal Functions
function openProfileModal() {
  document.getElementById('profile-modal').classList.remove('hidden');
  document.getElementById('edit-username').value = currentUser.username;
  document.getElementById('edit-bio').value = currentUser.bio || '';
  document.getElementById('preview-avatar').src = currentUser.profilePicture;
}

function closeModal(modalId) {
  document.getElementById(modalId).classList.add('hidden');
}

function previewProfilePicture() {
  const input = document.getElementById('profile-picture-input');
  const file = input.files[0];

  if (file) {
    const reader = new FileReader();
    reader.onload = (e) => {
      document.getElementById('preview-avatar').src = e.target.result;
    };
    reader.readAsDataURL(file);
  }
}

async function updateProfile() {
  const username = document.getElementById('edit-username').value.trim();
  const bio = document.getElementById('edit-bio').value.trim();
  const avatarSrc = document.getElementById('preview-avatar').src;
  const errorDiv = document.getElementById('profile-error');
  const successDiv = document.getElementById('profile-success');

  if (!username) {
    showError(errorDiv, 'Username is required');
    return;
  }

  try {
    const response = await fetch(`${API_URL}/api/user/profile`, {
      method: 'PUT',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${localStorage.getItem('token')}`
      },
      body: JSON.stringify({
        username,
        bio,
        profilePicture: avatarSrc
      })
    });

    const data = await response.json();

    if (!response.ok) {
      showError(errorDiv, data.error);
      return;
    }

    currentUser = data.user;
    localStorage.setItem('user', JSON.stringify(data.user));

    document.getElementById('user-name').textContent = currentUser.username;
    document.getElementById('user-avatar').src = currentUser.profilePicture;

    showSuccess(successDiv, 'Profile updated successfully!');
    setTimeout(() => closeModal('profile-modal'), 1500);
  } catch (error) {
    showError(errorDiv, 'Update failed: ' + error.message);
  }
}

// Admin Panel Functions
async function openAdminPanel() {
  document.getElementById('admin-modal').classList.remove('hidden');
  await loadAdminUsers();
}

async function loadAdminUsers() {
  try {
    const response = await fetch(`${API_URL}/api/admin/users`, {
      headers: {
        'Authorization': `Bearer ${localStorage.getItem('token')}`
      }
    });

    const users = await response.json();
    const tbody = document.getElementById('users-table-body');
    tbody.innerHTML = '';

    users.forEach(user => {
      const row = document.createElement('tr');
      row.innerHTML = `
        <td>${user.username}</td>
        <td>${user.email}</td>
        <td>
          <select onchange="changeUserRole('${user._id}', this.value)">
            <option value="user" ${user.role === 'user' ? 'selected' : ''}>User</option>
            <option value="moderator" ${user.role === 'moderator' ? 'selected' : ''}>Moderator</option>
            <option value="admin" ${user.role === 'admin' ? 'selected' : ''}>Admin</option>
          </select>
        </td>
        <td>${user.isBanned ? '<span style="color: red;">Banned</span>' : '<span style="color: green;">Active</span>'}</td>
        <td>
          <div class="admin-actions">
            ${!user.isBanned ? `<button class="btn-action danger" onclick="banUser('${user._id}')">Ban</button>` : `<button class="btn-action" onclick="unbanUser('${user._id}')">Unban</button>`}
          </div>
        </td>
      `;
      tbody.appendChild(row);
    });
  } catch (error) {
    console.error('Failed to load users:', error);
  }
}

async function banUser(userId) {
  const reason = prompt('Ban reason:');
  if (!reason) return;

  try {
    const response = await fetch(`${API_URL}/api/admin/ban-user`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${localStorage.getItem('token')}`
      },
      body: JSON.stringify({ userId, reason })
    });

    if (response.ok) {
      await loadAdminUsers();
    }
  } catch (error) {
    console.error('Failed to ban user:', error);
  }
}

async function unbanUser(userId) {
  try {
    const response = await fetch(`${API_URL}/api/admin/unban-user`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${localStorage.getItem('token')}`
      },
      body: JSON.stringify({ userId })
    });

    if (response.ok) {
      await loadAdminUsers();
    }
  } catch (error) {
    console.error('Failed to unban user:', error);
  }
}

async function changeUserRole(userId, role) {
  try {
    const response = await fetch(`${API_URL}/api/admin/change-role`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${localStorage.getItem('token')}`
      },
      body: JSON.stringify({ userId, role })
    });

    if (response.ok) {
      console.log('Role updated successfully');
    }
  } catch (error) {
    console.error('Failed to change role:', error);
  }
}

function switchAdminTab(tab) {
  document.querySelectorAll('.admin-tab').forEach(t => t.classList.add('hidden'));
  document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));

  document.getElementById(`${tab}-tab`).classList.remove('hidden');
  event.target.classList.add('active');
}

// Utility Functions
function showError(element, message) {
  element.textContent = message;
  element.classList.add('show');
}

function showSuccess(element, message) {
  element.textContent = message;
  element.classList.add('show');
  setTimeout(() => element.classList.remove('show'), 3000);
}
