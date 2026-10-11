const menuButton = document.querySelector('.menu-button');
const nav = document.querySelector('nav');
const appointmentForm = document.querySelector('#appointment-form');
const serviceTabs = document.querySelector('[role="tablist"]');

menuButton?.addEventListener('click', () => {
  const isOpen = nav.classList.toggle('open');
  menuButton.setAttribute('aria-expanded', isOpen);
});

nav?.querySelectorAll('a').forEach((link) => {
  link.addEventListener('click', () => {
    nav.classList.remove('open');
    menuButton.setAttribute('aria-expanded', 'false');
  });
});

serviceTabs?.addEventListener('click', (event) => {
  const selectedTab = event.target.closest('[role="tab"]');
  if (!selectedTab) return;

  serviceTabs.querySelectorAll('[role="tab"]').forEach((tab) => {
    const isSelected = tab === selectedTab;
    tab.setAttribute('aria-selected', String(isSelected));
    tab.tabIndex = isSelected ? 0 : -1;
  });

  serviceTabs.parentElement.querySelectorAll('[role="tabpanel"]').forEach((panel) => {
    panel.hidden = panel.id !== selectedTab.getAttribute('aria-controls');
  });
});

serviceTabs?.addEventListener('keydown', (event) => {
  const tabs = [...serviceTabs.querySelectorAll('[role="tab"]')];
  const currentIndex = tabs.indexOf(document.activeElement);
  let nextIndex;

  if (event.key === 'ArrowRight') nextIndex = (currentIndex + 1) % tabs.length;
  else if (event.key === 'ArrowLeft') nextIndex = (currentIndex - 1 + tabs.length) % tabs.length;
  else if (event.key === 'Home') nextIndex = 0;
  else if (event.key === 'End') nextIndex = tabs.length - 1;
  else return;

  event.preventDefault();
  tabs[nextIndex].focus();
  tabs[nextIndex].click();
});

appointmentForm?.addEventListener('submit', async (event) => {
  event.preventDefault();
  const notice = appointmentForm.querySelector('.notice');
  const button = appointmentForm.querySelector('button');
  button.disabled = true;
  notice.textContent = 'Sending your request...';
  notice.style.display = 'block';

  try {
    const response = await fetch(appointmentForm.action, {
      method: 'POST',
      body: new FormData(appointmentForm),
      headers: { Accept: 'application/json' }
    });
    const result = await response.json();

    if (!response.ok) throw new Error(result.message || 'Unable to send your request.');
    notice.textContent = result.message;
    appointmentForm.reset();
  } catch (error) {
    notice.textContent = error.message;
  } finally {
    button.disabled = false;
  }
});
