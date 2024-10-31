// static/js/main.js
$(document).ready(function() {
    $('#ftkOperationsForm').on('submit', function() {
      $(this).trigger("reset");
    });
  });
  