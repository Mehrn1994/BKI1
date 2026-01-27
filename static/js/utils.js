/* ========================================
   KESHAVARZI BANK CONFIG PORTAL
   Shared JavaScript Utilities v2.0
   ======================================== */

// ============================================
// AUTHENTICATION MODULE
// ============================================
const Auth = {
  getUsername() {
    return localStorage.getItem('currentUser') || 
           localStorage.getItem('username') || 
           sessionStorage.getItem('username');
  },
  
  setUsername(username) {
    localStorage.setItem('currentUser', username);
    sessionStorage.setItem('username', username);
  },
  
  logout() {
    localStorage.clear();
    sessionStorage.clear();
    window.location.href = 'login.html';
  },
  
  requireAuth() {
    const username = this.getUsername();
    if (!username) {
      window.location.href = 'login.html';
      return false;
    }
    return username;
  },
  
  displayUser(elementId = 'currentUser') {
    const el = document.getElementById(elementId);
    const username = this.getUsername();
    if (el && username) {
      el.textContent = username;
    }
  }
};

// ============================================
// TOAST NOTIFICATION SYSTEM
// ============================================
const Toast = {
  container: null,
  
  init() {
    if (this.container) return;
    
    this.container = document.createElement('div');
    this.container.className = 'toast-container';
    this.container.id = 'toastContainer';
    document.body.appendChild(this.container);
  },
  
  show(message, type = 'info', duration = 4000) {
    this.init();
    
    const icons = {
      success: `<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M20 6L9 17l-5-5"/></svg>`,
      error: `<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><path d="M15 9l-6 6M9 9l6 6"/></svg>`,
      warning: `<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 9v4M12 17h.01"/><path d="M10.29 3.86L1.82 18a2 2 0 001.71 3h16.94a2 2 0 001.71-3L13.71 3.86a2 2 0 00-3.42 0z"/></svg>`,
      info: `<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><path d="M12 16v-4M12 8h.01"/></svg>`
    };
    
    const colors = {
      success: '#10b981',
      error: '#ef4444',
      warning: '#f59e0b',
      info: '#3b82f6'
    };
    
    const toast = document.createElement('div');
    toast.className = 'toast';
    toast.style.borderLeftWidth = '4px';
    toast.style.borderLeftColor = colors[type];
    toast.innerHTML = `
      <span style="color: ${colors[type]}">${icons[type]}</span>
      <span style="flex: 1; color: var(--text-primary)">${message}</span>
      <button onclick="Toast.remove(this.parentElement)" style="background: none; border: none; color: var(--text-muted); cursor: pointer; padding: 4px;">
        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M18 6L6 18M6 6l12 12"/></svg>
      </button>
    `;
    
    this.container.appendChild(toast);
    
    if (duration > 0) {
      setTimeout(() => this.remove(toast), duration);
    }
    
    return toast;
  },
  
  remove(toast) {
    if (!toast || toast.classList.contains('removing')) return;
    toast.classList.add('removing');
    setTimeout(() => toast.remove(), 300);
  },
  
  success(message, duration) { return this.show(message, 'success', duration); },
  error(message, duration) { return this.show(message, 'error', duration); },
  warning(message, duration) { return this.show(message, 'warning', duration); },
  info(message, duration) { return this.show(message, 'info', duration); }
};

// ============================================
// MODAL SYSTEM
// ============================================
const Modal = {
  show(id) {
    const modal = document.getElementById(id);
    if (modal) {
      modal.classList.add('active');
      document.body.style.overflow = 'hidden';
    }
  },
  
  hide(id) {
    const modal = document.getElementById(id);
    if (modal) {
      modal.classList.remove('active');
      document.body.style.overflow = '';
    }
  },
  
  confirm(message, title = 'تایید') {
    return new Promise((resolve) => {
      const overlay = document.createElement('div');
      overlay.className = 'modal-overlay active';
      overlay.innerHTML = `
        <div class="modal">
          <div class="modal-header">
            <h3 class="modal-title">${title}</h3>
          </div>
          <div class="modal-body">
            <p>${message}</p>
          </div>
          <div class="modal-footer">
            <button class="btn btn-secondary" data-action="cancel">انصراف</button>
            <button class="btn btn-primary" data-action="confirm">تایید</button>
          </div>
        </div>
      `;
      
      document.body.appendChild(overlay);
      document.body.style.overflow = 'hidden';
      
      overlay.addEventListener('click', (e) => {
        const action = e.target.dataset.action;
        if (action) {
          overlay.classList.remove('active');
          setTimeout(() => {
            overlay.remove();
            document.body.style.overflow = '';
          }, 250);
          resolve(action === 'confirm');
        }
      });
    });
  }
};

// ============================================
// LOADING STATE MANAGER
// ============================================
const Loading = {
  show(element, text = 'Loading...') {
    if (typeof element === 'string') {
      element = document.getElementById(element);
    }
    if (!element) return;
    
    element.dataset.originalContent = element.innerHTML;
    element.disabled = true;
    element.innerHTML = `
      <span class="spinner spinner-sm"></span>
      <span>${text}</span>
    `;
  },
  
  hide(element) {
    if (typeof element === 'string') {
      element = document.getElementById(element);
    }
    if (!element) return;
    
    element.disabled = false;
    if (element.dataset.originalContent) {
      element.innerHTML = element.dataset.originalContent;
    }
  }
};

// ============================================
// API HELPER
// ============================================
const API = {
  async request(url, options = {}) {
    const defaultOptions = {
      headers: {
        'Content-Type': 'application/json'
      }
    };
    
    try {
      const response = await fetch(url, { ...defaultOptions, ...options });
      const data = await response.json();
      
      if (!response.ok) {
        throw new Error(data.error || data.message || 'Request failed');
      }
      
      return data;
    } catch (error) {
      console.error(`API Error [${url}]:`, error);
      throw error;
    }
  },
  
  get(url) {
    return this.request(url, { method: 'GET' });
  },
  
  post(url, body) {
    return this.request(url, {
      method: 'POST',
      body: JSON.stringify(body)
    });
  }
};

// ============================================
// CLIPBOARD UTILITY
// ============================================
const Clipboard = {
  async copy(text) {
    try {
      await navigator.clipboard.writeText(text);
      Toast.success('کپی شد!');
      return true;
    } catch (err) {
      console.error('Clipboard error:', err);
      Toast.error('خطا در کپی کردن');
      return false;
    }
  },
  
  copyFromElement(elementId) {
    const el = document.getElementById(elementId);
    if (el) {
      return this.copy(el.textContent || el.value);
    }
    return Promise.resolve(false);
  }
};

// ============================================
// FORM UTILITIES
// ============================================
const Form = {
  validate(formId) {
    const form = document.getElementById(formId);
    if (!form) return false;
    
    const requiredFields = form.querySelectorAll('[required]');
    let isValid = true;
    
    requiredFields.forEach(field => {
      this.clearError(field);
      
      if (!field.value.trim()) {
        this.setError(field, 'این فیلد الزامی است');
        isValid = false;
      }
    });
    
    return isValid;
  },
  
  setError(field, message) {
    field.classList.add('error');
    field.style.borderColor = 'var(--error)';
    
    let errorEl = field.parentNode.querySelector('.form-error');
    if (!errorEl) {
      errorEl = document.createElement('div');
      errorEl.className = 'form-error';
      field.parentNode.appendChild(errorEl);
    }
    errorEl.textContent = message;
  },
  
  clearError(field) {
    field.classList.remove('error');
    field.style.borderColor = '';
    
    const errorEl = field.parentNode.querySelector('.form-error');
    if (errorEl) errorEl.remove();
  },
  
  getData(formId) {
    const form = document.getElementById(formId);
    if (!form) return {};
    
    const formData = new FormData(form);
    const data = {};
    
    for (let [key, value] of formData.entries()) {
      data[key] = value;
    }
    
    return data;
  },
  
  reset(formId) {
    const form = document.getElementById(formId);
    if (form) {
      form.reset();
      form.querySelectorAll('.form-error').forEach(el => el.remove());
      form.querySelectorAll('.error').forEach(el => {
        el.classList.remove('error');
        el.style.borderColor = '';
      });
    }
  }
};

// ============================================
// DATE/TIME UTILITIES
// ============================================
const DateTime = {
  formatPersian(dateStr) {
    if (!dateStr) return '-';
    const date = new Date(dateStr);
    return date.toLocaleString('fa-IR', {
      year: 'numeric',
      month: '2-digit',
      day: '2-digit',
      hour: '2-digit',
      minute: '2-digit'
    });
  },
  
  formatRelative(dateStr) {
    if (!dateStr) return '-';
    const date = new Date(dateStr);
    const now = new Date();
    const diff = now - date;
    
    const minutes = Math.floor(diff / 60000);
    const hours = Math.floor(diff / 3600000);
    const days = Math.floor(diff / 86400000);
    
    if (minutes < 1) return 'همین الان';
    if (minutes < 60) return `${minutes} دقیقه پیش`;
    if (hours < 24) return `${hours} ساعت پیش`;
    if (days < 7) return `${days} روز پیش`;
    
    return this.formatPersian(dateStr);
  }
};

// ============================================
// IP ADDRESS UTILITIES
// ============================================
const IPUtils = {
  validate(ip) {
    const pattern = /^(\d{1,3}\.){3}\d{1,3}$/;
    if (!pattern.test(ip)) return false;
    
    const parts = ip.split('.');
    return parts.every(part => {
      const num = parseInt(part, 10);
      return num >= 0 && num <= 255;
    });
  },
  
  extractOctets(ip) {
    if (!this.validate(ip)) return null;
    const parts = ip.split('.');
    return {
      octet1: parseInt(parts[0]),
      octet2: parseInt(parts[1]),
      octet3: parseInt(parts[2]),
      octet4: parseInt(parts[3])
    };
  },
  
  getNetwork(ip, mask = 24) {
    const octets = this.extractOctets(ip);
    if (!octets) return null;
    
    if (mask === 24) {
      return `${octets.octet1}.${octets.octet2}.${octets.octet3}.0`;
    }
    // Add more mask calculations as needed
    return ip;
  },
  
  incrementIP(ip) {
    const octets = this.extractOctets(ip);
    if (!octets) return null;
    
    octets.octet4++;
    if (octets.octet4 > 255) {
      octets.octet4 = 0;
      octets.octet3++;
    }
    
    return `${octets.octet1}.${octets.octet2}.${octets.octet3}.${octets.octet4}`;
  },
  
  mirror200to201(ip) {
    const parts = ip.split('.');
    if (parts[0] === '10' && parts[1] === '200') {
      parts[1] = '201';
    }
    return parts.join('.');
  }
};

// ============================================
// LOCAL STORAGE UTILITY
// ============================================
const Storage = {
  set(key, value) {
    try {
      localStorage.setItem(key, JSON.stringify(value));
      return true;
    } catch (e) {
      console.error('Storage set error:', e);
      return false;
    }
  },
  
  get(key, defaultValue = null) {
    try {
      const item = localStorage.getItem(key);
      return item ? JSON.parse(item) : defaultValue;
    } catch (e) {
      console.error('Storage get error:', e);
      return defaultValue;
    }
  },
  
  remove(key) {
    localStorage.removeItem(key);
  }
};

// ============================================
// DEBOUNCE & THROTTLE
// ============================================
function debounce(func, wait = 300) {
  let timeout;
  return function executedFunction(...args) {
    const later = () => {
      clearTimeout(timeout);
      func(...args);
    };
    clearTimeout(timeout);
    timeout = setTimeout(later, wait);
  };
}

function throttle(func, limit = 300) {
  let inThrottle;
  return function(...args) {
    if (!inThrottle) {
      func.apply(this, args);
      inThrottle = true;
      setTimeout(() => inThrottle = false, limit);
    }
  };
}

// ============================================
// INITIALIZATION
// ============================================
document.addEventListener('DOMContentLoaded', () => {
  // Initialize toast container
  Toast.init();
  
  // Close modals on escape key
  document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape') {
      document.querySelectorAll('.modal-overlay.active').forEach(modal => {
        modal.classList.remove('active');
        document.body.style.overflow = '';
      });
    }
  });
  
  // Close modals on overlay click
  document.addEventListener('click', (e) => {
    if (e.target.classList.contains('modal-overlay')) {
      e.target.classList.remove('active');
      document.body.style.overflow = '';
    }
  });
  
  console.log('🚀 Config Portal Utilities Loaded');
});

// Export for module usage
if (typeof module !== 'undefined' && module.exports) {
  module.exports = {
    Auth, Toast, Modal, Loading, API, Clipboard, Form, DateTime, IPUtils, Storage,
    debounce, throttle
  };
}
