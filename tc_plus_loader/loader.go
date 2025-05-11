package main

import (
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"os"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

type MyCollection struct {
	TargetIPMap *ebpf.Map     `ebpf:"target_ip_map"`
	TrapIPsMap  *ebpf.Map     `ebpf:"trap_ips_map2"`
	XDPTrapProg *ebpf.Program `ebpf:"xdp_trap_monitor"`
}

func (objs *MyCollection) Close() error {
	if err := objs.TargetIPMap.Close(); err != nil {
		return err
	}
	if err := objs.TrapIPsMap.Close(); err != nil {
		return err
	}
	if err := objs.XDPTrapProg.Close(); err != nil {
		return nil
	}
	return nil
}

// Функция для записи IP-адреса в eBPF-карту
func setTargetIP(ipAddr string, targetIPMap *ebpf.Map) error {
	parsedIP := net.ParseIP(ipAddr)
	if parsedIP == nil {
		return fmt.Errorf("неверный IP-адрес: %s", ipAddr)
	}

	// Преобразуем IP-адрес в формат little-endian
	ip := binary.LittleEndian.Uint32(parsedIP.To4())
	key := uint32(0) // Всегда один элемент в target_ip_map

	// Запись IP в карту
	if err := targetIPMap.Put(key, ip); err != nil {
		return fmt.Errorf("не удалось записать IP в target_ip_map: %v", err)
	}

	log.Printf("IP-адрес ловушки %s загружен в target_ip_map", ipAddr)
	return nil
}

func main() {
	// Remove resource limits for kernels <5.11.
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal("Removing memlock:", err)
	}

	ifaceName := os.Getenv("INTERFACE")
	if ifaceName == "" {
		log.Fatalf("Не указан интерфейс. Укажите его через переменную окружения INTERFACE")
	}

	trapIP := os.Getenv("TRAP_IP")
	if trapIP == "" {
		log.Fatalf("Не указан IP ловушки. Укажите его через переменную окружения TRAP_IP")
	}

	// Находим интерфейс
	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		log.Fatalf("Не удалось найти интерфейс %s: %v", ifaceName, err)
	}

	// Загружаем eBPF программу
	spec, err := ebpf.LoadCollectionSpec("prog.o")
	if err != nil {
		log.Fatalf("Ошибка загрузки eBPF программы: %v", err)
	}

	log.Println("Карты - ", spec.Maps)
	log.Println("Program - ", spec.Programs)

	var myCol MyCollection

	// Создаем пустую коллекцию для хранения карт и программ
	// collection := &ebpf.Collection{}
	if err := spec.LoadAndAssign(&myCol, nil); err != nil {
		log.Fatalf("Ошибка загрузки eBPF программы в ядро: %v", err)
	}

	fmt.Println("Вот мапа TargetIPMap - ", myCol.TargetIPMap)
	fmt.Println("Вот мапа TrapIPsMap - ", myCol.TrapIPsMap)
	fmt.Println("Вот XDPTrapProg - ", myCol.XDPTrapProg)

	if err := setTargetIP(trapIP, myCol.TargetIPMap); err != nil {
		log.Fatal("В карту не загружены данные - IP адрес ловушки")
	} else {
		fmt.Println("В карту успешно загружен IP адрес ловушки")
	}

	xdpLink, err := link.AttachXDP(link.XDPOptions{
		Program:   myCol.XDPTrapProg,
		Interface: iface.Index,
	})
	if err != nil {
		log.Fatalf("Ошибка при прикреплении eBPF программы: %v", err)
	}
	defer xdpLink.Close()

	log.Println("eBPF программа успешно загружена на интерфейс", ifaceName)

	// Периодическое чтение карты trap_ips_map2 и вывод логов для обнаружения новых IP
	trapIPsMap := myCol.TrapIPsMap

	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		var key, nextKey uint32
		for {
			err := trapIPsMap.NextKey(&key, &nextKey)
			if err == ebpf.ErrKeyNotExist {
				break // Конец карты
			}
			if err != nil {
				log.Printf("Ошибка чтения карты trap_ips_map2: %v", err)
				break
			}

			// Получаем значение (количество обращений) для каждого IP
			var count uint32
			if err := trapIPsMap.Lookup(&nextKey, &count); err != nil {
				log.Printf("Ошибка получения данных для IP %v: %v", nextKey, err)
				continue
			}

			// Конвертируем IP из uint32 в строковый формат
			ipBytes := make(net.IP, 4)
			binary.BigEndian.PutUint32(ipBytes, nextKey)
			log.Printf("Обнаружено обращение с IP: %s, количество: %d", ipBytes.String(), count)
		}
	}
}

