jQuery(document).ready(function($) {
//   alert('kavi') ;

    $('#creport').click(function() {
        $('.creport,#closebtn').css({
            'display': 'block'
        });
    });
    $('#closebtn').click(function() {
        $('.creport,#closebtn').css({
            'display': 'none'
        });
    });





//    $('[placeholder]').focus(function() {
//        var input = $(this);
//        if (input.val() == input.attr('placeholder')) {
//            input.val('');
//            input.removeClass('placeholder');
//        }
//    }).blur(function() {
//        var input = $(this);
//        if (input.val() == '' || input.val() == input.attr('placeholder')) {
//            input.addClass('placeholder');
//            input.val(input.attr('placeholder'));
//        }
//    }).blur();
//
//
//
//    $('[placeholder]').parents('form').submit(function() {
//        $(this).find('[placeholder]').each(function() {
//            var input = $(this);
//            if (input.val() == input.attr('placeholder')) {
//                input.val('');
//            }
//        })
//    });






});


//$(function(){    
//    if($.browser.msie && $.browser.version <= 9){
//        $("[placeholder]").focus(function(){
//            if($(this).val()==$(this).attr("placeholder")) $(this).val("");
//        }).blur(function(){
//            if($(this).val()=="") $(this).val($(this).attr("placeholder"));
//        }).blur();
//
//        $("[placeholder]").parents("form").submit(function() {
//            $(this).find('[placeholder]').each(function() {
//                if ($(this).val() == $(this).attr("placeholder")) {
//                    $(this).val("");
//                }
//            })
//        });
//    }
//});


function onBlur(el) {
    if (el.value == '') {
        el.value = el.defaultValue;
    }
}
function onFocus(el) {
    if (el.value == el.defaultValue) {
        el.value = '';
    }
}



$(function() {
    $( ".from" ).datepicker({
      defaultDate: "+1w",
      changeMonth: true,
      numberOfMonths: 1,
      onClose: function( selectedDate ) {
        $( "#to" ).datepicker( "option", "minDate", selectedDate );
      }
    });
    $( ".to" ).datepicker({
      defaultDate: "+1w",
      changeMonth: true,
      numberOfMonths: 1,
      onClose: function( selectedDate ) {
        $( "#from" ).datepicker( "option", "maxDate", selectedDate );
      }
    });
  });