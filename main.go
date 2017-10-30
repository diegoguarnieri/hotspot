package main

import (
   "fmt"
   "net/http"
   "log"
   "strings"

   iptables "github.com/coreos/go-iptables/iptables"
   conntrack "github.com/diegoguarnieri/go-conntrack/conntrack"
)

func server(response http.ResponseWriter, request *http.Request) {
   request.ParseForm()

   msg := "success"
   action := ""
   ip := ""
   mac := ""
   for param, value := range request.Form {
      //fmt.Println("key:", param)
      //fmt.Println("val:", value)

      if param == "action" {
         action = value[0]
      } else if param == "ip" {
         ip = value[0]
      } else if param == "mac" {
         mac = value[0]
      } else {
         msg = "invalid parameters"
      }
   }

   if msg == "success" && action != "" && mac != "" && ip != "" {
      if action == "add" {
         err := addRule(mac)
         if err != nil {
            msg = err.Error()
         }
         
      } else if action =="del" {
         //first, delete bypass rule of firewall
         err := delRule(mac)
         if err != nil {
            msg = err.Error()
         } else {
         
            //after, delete all connections
            err := delConnection(ip)
            if err != nil {
               msg = err.Error()
            }
         }
         
      } else {
         msg = "invalid parameters"
      }
   } else {
      msg = "invalid parameters"
   }
   msg = strings.Trim(msg,"\n")
   log.Printf("action: %v ip: %v mac: %v return: %v\n", action, ip, mac, msg)

   //response to client
   fmt.Fprintf(response, `{"return":"` + msg + `"}`)
}

//-t (table)
//-I/-A (chain)
//adiciona o mac address do cliente autenticado para bypass o desvio do firewall para o captive portal
//iptables -t mangle -I internet 1 -m mac --mac-source 34:36:3b:74:96:60 -j RETURN

func addRule(mac string) error {
   //ipv4
   ipt, err := iptables.New()
   if err != nil {
      log.Fatalf("New failed: %v\n", err)
      return err
   }

   table := "mangle"
   chain := "internet"

   exists, err := ipt.Exists(table, chain, "-m", "mac", "--mac-source", mac, "-j", "RETURN")
   if err != nil {
      return err
   } else if !exists {
      err = ipt.Insert(table, chain, 1, "-m", "mac", "--mac-source", mac, "-j", "RETURN")
      if err != nil {
         log.Printf("AppendUnique failed: %v\n", err)
         return err
      }
   }

   return nil
}


//apaga o bypass do firewall
//iptables -D internet -t mangle -m mac --mac-source 34:36:3B:74:96:60 -j RETURN

func delRule(mac string) error {
   //ipv4
   ipt, err := iptables.New()
   if err != nil {
      log.Fatalf("New failed: %v\n", err)
      return err
   }

   //TODO: needs to be config
   table := "mangle"
   chain := "internet"

   err = ipt.Delete(table, chain, "-m", "mac", "--mac-source", mac, "-j", "RETURN")
   if err != nil {
      log.Printf("Delete failed: %v\n", err)
      return err
   }

   return nil
}

func delConnection(ip string) error {
   ctrack, err := conntrack.New()
   if err != nil {
      log.Fatalf("New failed: %v\n", err)
      return err
   }
   
   err = ctrack.DeleteConnectionBySrcIp(ip)
   if err != nil {
      log.Printf("DeleteConnectionBySrcIp failed: %v\n", err)
      return err
   }
   
   return nil
}

func main() {
   http.HandleFunc("/", server)

   err := http.ListenAndServe("127.0.0.1:9090", nil)
   if err != nil {
      log.Fatalf("ListenAndServe failed: %v\n", err)
   }
}

