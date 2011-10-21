<?php

/**
 * @file
 * provide forms and basic settings admin stuff
 */ 

// menu callback requesting update from watchdog
// only respond if requester is in server list
function crossdog_updates() {   
  $headers = getallheaders();   
  // crossdog_output_json_error("<pre>". print_r($headers, 1) ."\n". print_r($_REQUEST, 1) . "</pre>" ;   
  // check that required data is here
  if (!isset($_REQUEST['cmd'])) crossdog_output_json_error("Missing parameter 'cmd'");  
  if (!isset($_REQUEST['start_from'])) crossdog_output_json_error("Missing parameter 'start_from'"); 
  if (!isset($_REQUEST['ServerKey'])) crossdog_output_json_error("Missing parameter 'ServerKey'"); 
  if (!isset($_REQUEST['PublicKey'])) crossdog_output_json_error("Missing parameter 'PublicKey'"); 
  // if (!isset($headers['Host'])) crossdog_output_json_error("Missing header 'Host'"); 
  
  if ($_REQUEST['cmd'] === 'crossdog_update') {
    //$server = $headers['Host'];
    // if (!in_array($server, variable_get('crossdog_servers', array()))) { 
    //  crossdog_output_json_error("Rejected update request from unlisted server {$server}");  
    //}
    $server_key = (int) $_REQUEST['ServerKey'];
    if (!in_array($server_key, variable_get('crossdog_access_keys', array()))) {
      crossdog_output_json_error("Unrecognized server access key: {$server_key}");  
    }  
    $start_from = (int) $_REQUEST['start_from'];    
    $publickey = $_REQUEST['PublicKey'];
    $data = crossdog_matching_logs($start_from);  
    
    /*
    // if (!openssl_public_encrypt($data, $crypttext, $publickey)) {
    //   crossdog_output_json_error("Error encrypting data:  $data");  
    // }
    //$data = array('encrypted' => $crypttext); 
    $id = openssl_seal($data, $sealed, $ekeys, array($publickey));
    $data = array(
      'id'  => $id,
      'ekeys' => $ekeys,
      'sealed' => $sealed,
    );
    */
    crossdog_output_json($data); 
  }
}
function crossdog_output_json($data) {
  $json = json_encode($data); 
  header('Cache-Control: no-cache, must-revalidate');
  header('Expires: Mon, 26 Jul 1997 05:00:00 GMT');
  header('Content-type: application/json');
  header('Content-Length: ' . strlen($json));
  echo $json;
  exit;
}
function crossdog_output_json_error($msg) {
  $json = json_encode(array('error' => $msg)); 
  header('Cache-Control: no-cache, must-revalidate');
  header('Expires: Mon, 26 Jul 1997 05:00:00 GMT');
  header('HTTP/1.1 500 Internal Server Error');
  header('Content-type: application/json');
  header('Content-Length: ' . strlen($json));
  echo $json;
  exit;
}
 
function crossdog_check_for_client_updates_cronjob() { 
  crossdog_generate_keys(); // generates openssl key if needed
  
  // exit immediately if no clients known
  $crossdog_clients = variable_get('crossdog_clients', array());
  if (!count($crossdog_clients)) return; 
  // request updates from each client if we have not checked in the last 20 minutes
  $crossdog_last_checked = variable_get('crossdog_last_checked', strtotime("10 days ago")); 
  if ($crossdog_last_checked < strtotime("20 minutes ago")) {
    $new_data = FALSE;
    foreach ($crossdog_clients as $client) {   
       $client_url = "http://{$client}/admin/crossdog/updates"; 
       $client_last_timestamp = (int) db_query("SELECT MAX(timestamp) FROM {crossdog} WHERE log_site=:site",
          array(':site' => $client))->fetchField();
       //drupal_set_message("Requesting update from client {$client} ". l($client_url, $client_url));  
       $headers = array(   
         'Content-Type' => 'application/x-www-form-urlencoded'
       ); 
       $params = http_build_query(array(
         'ServerKey'     => variable_get('crossdog_server_key', ''),
         'PublicKey'    => variable_get('crossdog_publickey', ''),  
         'cmd'     => 'crossdog_update',
         'start_from'    => $client_last_timestamp,
       )); 
       $options = array(
         'method'  => 'POST',
         'data'    => $params, // necessary?
         'timeout' => 10, 
         'headers' => $headers,
       );
       $request = drupal_http_request($client_url, $options);
       $data = json_decode($request->data);  
       if ($request->code == 200) {
         if ($data) {
            // store data here
            foreach ($data as $wid => $entry) {
              // att the log_site client to the record
              $entry_found = db_query("SELECT cid FROM {crossdog} WHERE wid=:wid AND log_site=:client",
                array(':wid' => $entry->wid, ':client' => $client))->fetchField();
              if (!$entry_found) {
                $entry->log_site = $client; 
                $entry_array = get_object_vars($entry);
                drupal_set_message("Writing new log item from {$client}: {$entry->wid}"); 
                //drupal_write_record('crossdog', $entry_array);
                db_insert('crossdog')->fields($entry_array)->execute();
                //drupal_set_message("Written: <pre>". print_r($entry_array, 1) ."</pre>"); 
                //break;
              } 
            }
           //drupal_set_message("Received data from client {$client}: <pre>". print_r($data, 1) ."</pre>"); 
         } else { 
           drupal_set_message("Client {$client}: had no data for us."); 
         }
       } else { 
         drupal_set_message("Request failed from client {$client}, error: {$data->error}", 'warning'); 
       }
    }    
    variable_set('crossdog_last_checked', strtotime("now"));
  }  
  
}

// admin settings form
// set which servers to allow, which $request = drupal_http_request('http://www.example.com/'); 
function crossdog_admin_settings() {  
  crossdog_generate_keys(); // only has to be called once
  $form = array();   
  $crossdog_types = variable_get('crossdog_types', array());
  if (is_array($crossdog_types) && count($crossdog_types)) $crossdog_types = implode("\n", $crossdog_types);    
  $crossdog_severities = array_keys(variable_get('crossdog_severities', array()));   
 

  $form['log_rules'] = array(
    '#type'  =>  'fieldset',
    '#title' =>  t('Log Sharing Rules'), 
    '#description' => t('To share this site\'s watchdog logs with an aggregation server, define which types or severities '.
    'of logs you wish to share. Since log types are usually named after the module doing the logging, you can usually just '.
    'provide a module name to capture all logs from a certain module.'),
    '#collapsible' =>  TRUE, 
    '#collapsed' =>  ($crossdog_types && count($crossdog_severities)),
  ); 
  
  // types to record
  $form['log_rules']['crossdog_types'] = array(
    '#type' => 'textarea',
    '#title' => t('Log Types'),
    '#description' => t('Types of watchdog messages to share with aggregation server.') . 
      " Existing log entry types: <i><b>" . implode(", ", _dblog_get_message_types()) . '</b></i>',
    '#default_value' => $crossdog_types,
    '#cols' => 60,
    '#rows' => 5,
  );
  // severity levels to record
  $form['log_rules']['crossdog_severities'] = array(
    '#type' => 'checkboxes',
    '#title' => t('Log Severities'),
   '#description' => t('Levels of severities to share, default is none. (Leave empty if this site si the aggregation server.)'),
    '#default_value' => $crossdog_severities,
    '#options' =>  watchdog_severity_levels(),
  ); 
  // display logged items on client
  $form['log_rules']['crossdog_show_messages'] = array(
    '#type' => 'checkbox',
    '#title' => t('Onscreen notification on logged'),
    '#description' => t('Show onscreen message when an entry is logged which matches these rules'),
    '#default_value' => variable_get('crossdog_show_messages', FALSE), 
  ); 


  $crossdog_clients = variable_get('crossdog_clients', array());
  //if ($crossdog_clients && count($crossdog_clients)) 
  $crossdog_clients = implode("\n", $crossdog_clients);  
  $crossdog_servers = variable_get('crossdog_servers', array()); 
  if ($crossdog_servers && count($crossdog_servers)) $crossdog_servers = implode("\n", $crossdog_servers);  
 
  $server_access_key = variable_get('crossdog_server_key', '');  
  $form['client_server'] = array(
    '#type'  =>  'fieldset',
    '#title' =>  t('Client / Server Settings'), 
    '#collapsible' =>  TRUE, 
    '#collapsed' =>  FALSE, //($crossdog_clients && $crossdog_servers), 
    '#description' => t('Crossdog allows a website to act as an aggregation server to collect watchdog logs from '.
    'client websites. The same module provides both roles. To collect logs from another site, provide "Client Domains" '.
    'and to share this site\'s watchdog logs with an aggregation server, provide it\'s "Server Access Key"'),
  );  
  // clients to check
  $form['client_server']['crossdog_clients'] = array(
    '#type' => 'textarea',
    '#title' => t('Client Domains (if this is an aggregation server)'),
    '#description' => t('Optional: Act as an aggregation server and request logs from these websites.' ) . 
      "<br/><i>" .
      t('If this site is used as an aggregation server, its access key is') .
      "  <b>{$server_access_key}</b></i>", 
    '#default_value' => $crossdog_clients,
    '#cols' => 60,
    '#rows' => 3,
  );   
  
  if ($agg_count = db_query("SELECT count(*) FROM {crossdog}")->fetchField()) {
    // option to delete aggregated items
    $form['client_server']['crossdog_delete_all'] = array(
      '#type' => 'checkbox',
      '#title' => t('Delete @count aggregated logs', array('@count' => $agg_count)),
      '#description' => t('Permaently delete all aggregated data.'),
      '#default_value' => variable_get('crossdog_delete_all', FALSE), 
    ); 
  }
  
  // server access keys to accept  
  $form['client_server']['crossdog_access_keys'] = array(
    '#type' => 'textarea',
    '#title' => t('Server Access Keys (if this is a client)'),
    '#description' => t('Optional: Act as a client and provide log entries to servers matching one of these access keys.'),
    '#default_value' => implode("\n", variable_get('crossdog_access_keys', array())),
    '#cols' => 60,
    '#rows' => 1,
  );   
  
  $form['submit'] = array(
    '#type' => 'submit',
    '#value' => t('Save'),
  );

  return $form;
}
function crossdog_admin_settings_submit($form, &$form_state) {  
  $input = $form_state['input'];
  
  // crossdog_types
  $crossdog_types = array();
  if (isset($input['crossdog_types']) && ($types = $input['crossdog_types'])) { // needs split into keyed array
    $types = str_replace(",", "\n", $types);
    $types = explode("\n", $types);
    foreach ($types as $type) {
      $type = trim(strtolower($type));
      if ($type) $crossdog_types[$type] = $type;    
    }
  }
  variable_set('crossdog_types', $crossdog_types);
  
  // crossdog_severities 
  $crossdog_severities = array();
  if (isset($input['crossdog_severities']) && ($severities = $input['crossdog_severities'])) { // array, needs parsed and only keyed items left ?  
    foreach ($severities as $type) {
      $type = trim(strtolower($type));
      $crossdog_severities[$type] = $type;  
    }
  }
  variable_set('crossdog_severities', $crossdog_severities);
  
  // crossdog_clients
  $crossdog_clients = array();
  if (isset($input['crossdog_clients']) && ($clients = $input['crossdog_clients'])) { // needs split into keyed array
    $clients = explode("\n", $clients);
    foreach ($clients as $client) {
      $client = trim(strtolower($client));
      $client = str_replace(array('https://', 'http://'), '', $client); 
      $crossdog_clients[$client] = $client; 
    }
  }
  variable_set('crossdog_clients', $crossdog_clients); 
  
  // crossdog_access_keys
  $crossdog_access_keys = array();
  if (isset($input['crossdog_access_keys']) && ($keys = $input['crossdog_access_keys'])) { // needs split into keyed array
    $keys = str_replace(",", "\n", $keys);
    $keys = explode("\n", $keys);
    foreach ($keys as $key) {
      $key = (int) trim($key); 
      if ($key) $crossdog_access_keys[$key] = $key; 
    }
  }
  variable_set('crossdog_access_keys', $crossdog_access_keys);  
  
  // show drupal message on matching logs
  if (isset($input['crossdog_show_messages'])) {
    variable_set('crossdog_show_messages', $input['crossdog_show_messages']); 
  }
  else variable_set('crossdog_show_messages', array());  
  
  // delete matching logs  crossdog_delete_all
  if (isset($input['crossdog_delete_all']) && $input['crossdog_delete_all']) {
    db_delete('crossdog')->execute();  
  }
  
}


function crossdog_format_logitems($title, $logs) { 
 $severities = watchdog_severity_levels(); 
 $result = "<div class='site_group'><h3> {$title} </h3> <ul>";
 foreach ($logs as $log) { 
    $result .= "<li class='log_item'> <a href='#' class='show_more_link'>".
      "{$log->log_site}: " . 
      "<u>" . $log->type . "</u> / <u>". $severities[$log->severity] . "</u> ".
      date("D M j", $log->timestamp) . 
      "</a> ".
      ($log->user_name ? " (" . $log->user_name . ") " : " ") .
      t($log->message, unserialize($log->variables)) .
      // " <a href='#' class='show_more_link'>[more...]</a>" .
      "<div class='more_info'>" .
      "<pre>" . print_r(unserialize($log->variables), 1) . "</pre> " .
      "</div>" .
      "</li>";
  }
  $result = "{$result} </ul></div>";
  return $result;
}

// example custom report for server
// use this as an example for building more specialized reports
function crossdog_basic_report() {
  drupal_add_css(drupal_get_path('module', 'crossdog') . '/crossdog.css');
  drupal_add_js(drupal_get_path('module', 'crossdog') . '/crossdog.js');
  // show all entities, breaking them up by site and ordering by most recent message
  // perhaps show most recent 10 items with "show more" JS link
  
  // first, we'll use this to show matching logs
  crossdog_check_for_client_updates_cronjob();
  
  $result = "<h2> Aggregated Watchdog Logs </h2>";
  
  // most recent actions
  $logs = db_query('SELECT * FROM {crossdog} ORDER BY timestamp DESC LIMIT 10')->fetchAll(); 
  $result .= crossdog_format_logitems('Most Recent Logs', $logs);  
  
  $log_sites = db_query('SELECT DISTINCT(log_site) FROM {crossdog}')->fetchCol();
  foreach($log_sites as $log_site) {
    $logs = db_query('SELECT * FROM {crossdog} WHERE log_site=:log_site ORDER BY timestamp DESC LIMIT 10',
      array(':log_site' => $log_site))->fetchAll(); 
    $result .= crossdog_format_logitems($log_site, $logs);  // need more link
  }
  
  /*
  $logs = db_query('SELECT * FROM {crossdog} ORDER BY timestamp DESC  ')->fetchAll();
  foreach($logs as $log) {
    $ordered_sites[$log->log_site][] = $log;  
  }
  
  // , array(':limit' => count($sites)*20)
  
  $result .= "<pre>". print_r($ordered_sites, 1) . "</pre>";
  */
  
  // get list of all domains  
  // get 10 most recent items per domain
  // sort domains by most recent
  // display summary of last 30 days
  // display 10 most recent messags by date 
  // display each domain  with 10 items and a more link
  
  
   /* drupal_set_message("<pre>" . print_r(array(
    'crossdog_types' => $crossdog_types,
    'crossdog_severities' => $crossdog_severities,
    'crossdog_clients' => $crossdog_clients,
    'crossdog_servers' => $crossdog_servers,  
  ), 1) . "</pre>");
  */ 
  
  
  return $result;
}

 

// fetch matching watchdog posts after the last checked date
function crossdog_matching_logs($timestamp = 0) { 
  $crossdog_types = array_keys(variable_get('crossdog_types', array()));
  $crossdog_severities = array_keys(variable_get('crossdog_severities', array()));  
  $sql ="SELECT w.*, u.name user_name, u.mail user_mail FROM {watchdog} w, {users} u 
    WHERE w.timestamp > :timestamp
     AND ((w.severity IN (:crossdog_severities)) OR (w.type IN (:crossdog_types)))
     AND w.uid = u.uid"; 
  $result = db_query($sql, array(
    ':timestamp' => $timestamp, 
    ':crossdog_severities' => $crossdog_severities, 
    ':crossdog_types' => $crossdog_types,
  ));  
  return $result->fetchAllAssoc('wid');   
}

function crossdog_generate_keys() { 
  if (!variable_get('crossdog_publickey', '')) {
    // Create the keypair
    $res = openssl_pkey_new();
    // Get private key
    openssl_pkey_export($res, $privatekey);
    variable_set('crossdog_privatekey', $privatekey);
    // Get public key
    $publickey = openssl_pkey_get_details($res); 
    variable_set('crossdog_publickey', $publickey["key"]);
    // set a server access key based on the generated public key
    variable_set('crossdog_server_key', crossdog_crc16($publickey["key"])); 
  }  
}

function crossdog_crc16($data) {
  $crc = 0xFFFF;
  for ($i = 0; $i < strlen($data); $i++)   {
    $x = (($crc >> 8) ^ ord($data[$i])) & 0xFF;
    $x ^= $x >> 4;
    $crc = (($crc << 8) ^ ($x << 12) ^ ($x << 5) ^ $x) & 0xFFFF;
  }
  return $crc;
}

function crossdog_log_entry_match($log_entry) {
  return (crossdog_messagetype_match($log_entry['type']) || 
    crossdog_severity_match($log_entry['severity'])); 
}

function crossdog_severity_match($severity) {
  $crossdog_severities = variable_get('crossdog_severities', array());
  return in_array($severity, $crossdog_severities);
}

function crossdog_addtype($type) { 
  $types = variable_get('crossdog_types', array());
  $types[$type] = $type;
  variable_set('crossdog_types', $types);
} 

function crossdog_messagetype_match($message_type) {
  return in_array($message_type, variable_get('crossdog_types', array())); 
}



