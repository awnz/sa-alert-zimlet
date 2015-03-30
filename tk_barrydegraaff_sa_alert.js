/*
This file is part of the Spam Assassin Alert Zimlet.
Copyright (C) 2015  Barry de Graaff

Bugs and feedback: https://github.com/barrydegraaff/sa-alert-zimlet

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see http://www.gnu.org/licenses/.
*/
/**
 * This zimlet checks for X-Spam-Status message header and alerts the user when certain tags are found.
 */
function tk_barrydegraaff_sa_alert_HandlerObject() {
}

tk_barrydegraaff_sa_alert_HandlerObject.prototype = new ZmZimletBase();
tk_barrydegraaff_sa_alert_HandlerObject.prototype.constructor = tk_barrydegraaff_sa_alert_HandlerObject;

/**
 * Simplify handler object
 *
 */
var SA_AlertZimlet = tk_barrydegraaff_sa_alert_HandlerObject;

/**
 * Initializes the zimlet.
 */
SA_AlertZimlet.prototype.init =
function() {
   AjxPackage.require({name:"MailCore", callback:new AjxCallback(this, this._applyRequestHeaders)});
};

/**
 * Applies the request headers.
 * 
 */
SA_AlertZimlet.prototype._applyRequestHeaders =
function() {	
	ZmMailMsg.requestHeaders["X-Spam-Status"] = "X-Spam-Status";
};

SA_AlertZimlet.prototype.onMsgView = function (msg, oldMsg, view) {  
   try
   {
      if(
         (msg.attrs['X-Spam-Status'].indexOf('URI_PHISH') > 0) ||
         (msg.attrs['X-Spam-Status'].indexOf('HTTPS_HTTP_MISMATCH') > 0) ||
         (msg.attrs['X-Spam-Status'].indexOf('URIBL_DBL_ABUSE_PHISH') > 0) ||
         (msg.attrs['X-Spam-Status'].indexOf('RCVD_IN_BRBL_LASTEXT') > 0) ||
         (msg.attrs['X-Spam-Status'].indexOf('RCVD_IN_BL_SPAMCOP_NET') > 0)
      )
      {
         SA_AlertZimlet.prototype._dialog = new ZmDialog( { title:'Phising mail detected', parent:this.getShell(), standardButtons:[DwtDialog.OK_BUTTON], disposeOnPopDown:true } );
         SA_AlertZimlet.prototype._dialog.setContent('ATTENTION: This is probably a phishing mail, do not click on any links in the mail.<br><br>Please mark the message as junk');
         SA_AlertZimlet.prototype._dialog.popup();
   
      }
   } catch (err)
   {
     // X-Spam-Status header not found  
   }
}   
