(function ($) {
  'use strict';
  $(function () {
    $('.sss-copy').on('click', function (e) {
      e.preventDefault();
      var target = $($(this).data('target'));
      if (!target.length) return;
      var text = target.text();
      if (navigator.clipboard) {
        navigator.clipboard.writeText(text);
      }
      $(this).text('Copied');
    });
  });
})(jQuery);
