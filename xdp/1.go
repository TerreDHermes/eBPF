package main

import (
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"os/exec"
	"sync"
	"time"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

const MTU_LIMIT = 900

// IP-заголовок
type IPHeader struct {
	VersionIHL uint8
	TOS        uint8
	Length     uint16
	ID         uint16
	FragOff    uint16
	TTL        uint8
	Protocol   uint8
	Checksum   uint16
	Src        [4]byte
	Dst        [4]byte
}

// Контрольная сумма ICMP
func csum(data []byte) uint16 {
	var sum uint32
	for i := 0; i < len(data)-1; i += 2 {
		sum += uint32(data[i])<<8 | uint32(data[i+1])
	}
	if len(data)%2 == 1 {
		sum += uint32(data[len(data)-1]) << 8
	}
	sum = (sum >> 16) + (sum & 0xffff)
	sum += (sum >> 16)
	return ^uint16(sum)
}

// Отправляет ICMP-сообщение "Фрагментация необходима"
func sendICMP(srcIP, dstIP [4]byte, mtu int) error {
	addrStr := fmt.Sprintf("%d.%d.%d.%d", dstIP[0], dstIP[1], dstIP[2], dstIP[3])
	conn, err := net.Dial("ip4:icmp", addrStr)
	if err != nil {
		log.Printf("Не удалось установить соединение: %v", err)
		return err
	}
	defer conn.Close()

	// ICMP-пакет
	icmpPacket := make([]byte, 8)
	icmpPacket[0] = 3                                       // Тип: Destination unreachable
	icmpPacket[1] = 4                                       // Код: Fragmentation needed
	binary.BigEndian.PutUint16(icmpPacket[4:], uint16(mtu)) // Следующий допустимый MTU

	checksum := csum(icmpPacket)
	binary.BigEndian.PutUint16(icmpPacket[2:], checksum)

	_, err = conn.Write(icmpPacket)
	if err != nil {
		log.Printf("Ошибка отправки ICMP: %v", err)
		return err
	}
	fmt.Println("Отправлено ICMP-сообщение \"Fragmentation needed\"")
	return nil
}

// Сборщик объектов
type Collection struct {
	PacketQueue *ebpf.Map     `ebpf:"packet_map"`
	XDPProg     *ebpf.Program `ebpf:"monitor"`
}

// Главный процесс
func main() {
	interfaceName := "enp0s3"

	// Повышаем лимит памяти ядра
	err := rlimit.RemoveMemlock()
	if err != nil {
		log.Fatal(err)
	}

	// Очищаем предыдущий фильтр
	cmd := fmt.Sprintf("ip link set dev %s xdpgeneric off", interfaceName)
	out, err := exec.Command("bash", "-c", cmd).CombinedOutput()
	if err != nil {
		log.Printf("Ошибка выполнения команды: %v\nВывод:\n%s", err, out)
	}

	// Объекты eBPF
	var coll Collection
	spec, err := ebpf.LoadCollectionSpec("xdp_icmp_monitor.o")
	if err != nil {
		log.Fatalf("Ошибка загрузки eBPF-программы: %v", err)
	}

	// Загружаем объекты
	if err := spec.LoadAndAssign(&coll, nil); err != nil {
		log.Fatalf("Ошибка загрузки карт и программ: %v", err)
	}

	// Прикрепляем XDP-программу к интерфейсу
	xdpLink, err := link.AttachXDP(link.XDPOptions{
		Program:   coll.XDPProg,
		Interface: ifaceByName(interfaceName),
	})
	if err != nil {
		log.Fatalf("Ошибка прикрепления XDP-программы: %v", err)
	}
	defer xdpLink.Close()

	// Запускаем обработчик очереди
	go processPackets(coll.PacketQueue)

	log.Println("Ожидаем событий...")
	select {} // Безконечность
}

// Получаем индекс интерфейса по имени
func ifaceByName(name string) int {
	iface, err := net.InterfaceByName(name)
	if err != nil {
		log.Fatalf("Ошибка определения индекса интерфейса '%s': %v", name, err)
	}
	return iface.Index
}

// Обрабатываем входящие пакеты из очереди
func processPackets(packetQueue *ebpf.Map) {
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		ticker := time.NewTicker(time.Second)
		defer ticker.Stop()

		for range ticker.C {
			// Забираем первый элемент из очереди
			buf := make([]byte, 20) // Размер IP-заголовка
			key := uint32(0)        // Начинаем с ключа 0
			err := packetQueue.LookupAndDelete(&key, &buf)
			if err != nil {
				continue
			}

			// Парсим IP-заголовок
			ipHdr, valid := parseIP(buf)
			if !valid {
				continue
			}

			srcIP := ipHdr.Src
			dstIP := ipHdr.Dst

			// Отправляем ICMP уведомление о фрагментации
			sendICMP(srcIP, dstIP, MTU_LIMIT)
		}
	}()
	wg.Wait()
}

// Парсер IP-заголовка
func parseIP(data []byte) (*IPHeader, bool) {
	if len(data) < 20 { // Минимальная длина IPv4-заголовка
		return nil, false
	}
	ipHdr := new(IPHeader)
	copy((*[20]byte)(unsafe.Pointer(ipHdr))[:], data[:20])
	return ipHdr, true
}
