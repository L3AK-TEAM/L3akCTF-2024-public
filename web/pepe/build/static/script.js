"use strict";

// links
const sideLInksEl = document.querySelectorAll(
  ".sidebar .side-menu li a:not(.logout)",
);

sideLInksEl.forEach((links) => {
  const li = links.parentElement;
  links.addEventListener("click", () => {
    sideLInksEl.forEach((i) => {
      i.parentElement.classList.remove("active");
    });
    li.classList.add("active");
  });
});

// sidebar
const menuBar = document.querySelector(".content nav .bx.bx-menu");
const sideBarEl = document.querySelector(".sidebar");

// menus
menuBar.addEventListener("click", () => {
  sideBarEl.classList.toggle("close");
});

const searchbtn = document.querySelector(
  ".content nav form .form-input button",
);
const searchIcon = document.querySelector(
  ".content nav form .form-input button .bx",
);
const searchForm = document.querySelector(".content nav form");

searchbtn.addEventListener("click", function (e) {
  if (window.innerWidth < 576) {
    e.preventDefault;
    searchForm.classList.toggle("show");

    if (searchForm.classList.contains("show")) {
      searchIcon.classList.replace("bx-search", "bx-x");
    } else {
      searchIcon.classList.replace("bx-x", "bx-search");
    }
  }
});

// resize
window.addEventListener("resize", () => {
  if (window.innerWidth < 768) {
    sideBarEl.classList.add("close");
  } else {
    sideBarEl.classList.remove("close");
  }
});

// dark and light mode
const darkEl = document.querySelector(".side-menu ul li a");
const darkIcon = document.querySelector(".side-menu ul li .bx.bx-moon");

darkEl.addEventListener("click", () => {
  document.body.classList.toggle("dark");

  if (document.body.classList.contains("dark")) {
    darkIcon.classList.replace("bx-moon", "bx-sun");
  } else {
    darkIcon.classList.replace("bx-sun", "bx-moon");
  }
});