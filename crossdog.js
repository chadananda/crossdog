 
jQuery(function() { 
  jQuery("a.show_more_link").click(function() { 
      jQuery(this).parent().find('div.more_info').toggle();   
      return false;
  });  
});

