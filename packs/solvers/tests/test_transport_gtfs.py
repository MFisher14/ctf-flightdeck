"""Independent CSV fixtures and MobilityData's generated protobuf as oracle."""
import io
import math
import random
import zipfile

import pytest
from google.transit import gtfs_realtime_pb2 as pb

from transport_gtfs import (
    TransportGTFSError, decode_gtfs_rt, main, parse_gtfs_zip,
    service_seconds, trip_itinerary,
)


def zipped(tables):
    out = io.BytesIO()
    with zipfile.ZipFile(out, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for name, data in tables.items():
            archive.writestr(name, data)
    return out.getvalue()


TABLES = {
    "routes.txt": "route_id,route_short_name,route_type\n007,Harbour,3\n",
    "trips.txt": "route_id,service_id,trip_id,shape_id\n007,WK,T1,S1\n",
    "stops.txt": 'stop_id,stop_name,stop_lat,stop_lon\n001,"Dock, East",44.4,26.1\n002,Depot,44.5,26.2\n',
    "stop_times.txt": "trip_id,arrival_time,departure_time,stop_id,stop_sequence\nT1,25:15:00,25:16:00,002,20\nT1,24:50:00,24:50:30,001,10\n",
    "calendar.txt": "service_id,monday,tuesday,wednesday,thursday,friday,saturday,sunday,start_date,end_date\nWK,1,1,1,1,1,0,0,20260101,20261231\n",
    "calendar_dates.txt": "service_id,date,exception_type\nWK,20261106,2\nWK,20261107,1\n",
    "shapes.txt": "shape_id,shape_pt_lat,shape_pt_lon,shape_pt_sequence\nS1,44.5,26.2,9\nS1,44.4,26.1,3\n",
    "feed_info.txt": "feed_publisher_name,feed_publisher_url,feed_lang\nCSCTF{offline_transit},https://example.invalid,en\n",
}


def test_static_preserves_ids_quoted_csv_and_flags():
    feed = parse_gtfs_zip(zipped(TABLES))
    assert feed["tables"]["routes.txt"][0]["route_id"] == "007"
    assert feed["tables"]["stops.txt"][0]["stop_name"] == "Dock, East"
    assert feed["flags"] == ["CSCTF{offline_transit}"]
    route = trip_itinerary(feed, "T1")
    assert route["route"]["route_short_name"] == "Harbour"
    assert [row["stop"]["stop_id"] for row in route["stops"]] == ["001", "002"]
    assert route["stops"][1]["arrival_time_seconds"] == 25 * 3600 + 15 * 60
    assert route["shape"] == [
        {"sequence": 3, "latitude": 44.4, "longitude": 26.1},
        {"sequence": 9, "latitude": 44.5, "longitude": 26.2},
    ]


@pytest.mark.parametrize("date,active", [("20261105", True), ("20261106", False), ("20261107", True), ("20261108", False), ("20270101", False)])
def test_weekly_service_and_exceptions(date, active):
    assert trip_itinerary(parse_gtfs_zip(zipped(TABLES)), "T1", date)["active"] is active


def test_partial_feed_calendar_unknown_and_added_service():
    tables = {k: v for k, v in TABLES.items() if not k.startswith("calendar")}
    assert trip_itinerary(parse_gtfs_zip(zipped(tables)), "T1", "20261106")["active"] is None
    tables["calendar_dates.txt"] = "service_id,date,exception_type\nWK,20261106,1\n"
    feed = parse_gtfs_zip(zipped(tables))
    assert trip_itinerary(feed, "T1", "20261106")["active"] is True
    assert trip_itinerary(feed, "T1", "20261105")["active"] is False


@pytest.mark.parametrize("value,expected", [("0:00:00", 0), ("24:00:01", 86401), ("123:59:59", 446399)])
def test_service_clock(value, expected):
    assert service_seconds(value) == expected


@pytest.mark.parametrize("value", [None, b"12:00:00", "12:60:00", "-1:00:00", "12:00", "12:00:99", "NaN"])
def test_bad_service_clock(value):
    with pytest.raises(TransportGTFSError):
        service_seconds(value)


@pytest.mark.parametrize("tables", [
    {"../stops.txt": "stop_id\n1\n"}, {"sub/stops.txt": "stop_id\n1\n"},
    {"stops.txt": "stop_id,stop_id\n1,2\n"}, {"stops.txt": "stop_id\n1,2\n"},
    {"stops.txt": 'stop_id\n"unclosed'}, {"stops.txt": b"\xff"},
    {"stops.txt": "stop_id\n\x00\n"}, {"image.png": b"abc"},
    {"unrelated.txt": "name\nthing\n"},
])
def test_bad_archives(tables):
    with pytest.raises(TransportGTFSError):
        parse_gtfs_zip(zipped(tables))


def test_unknown_non_csv_and_utf8_bom():
    feed = parse_gtfs_zip(zipped({"stops.txt": "\ufeffstop_id,stop_name\n1,Station\n", "locations.geojson": "{}"}))
    assert feed["tables"]["stops.txt"][0]["stop_id"] == "1"
    assert feed["unparsed_files"] == ["locations.geojson"]


def test_archive_resource_limit_and_bad_crc(monkeypatch):
    import transport_gtfs
    raw = zipped({"stops.txt": "stop_id\n" + "1\n" * 100})
    monkeypatch.setattr(transport_gtfs, "MAX_EXPANDED", 100)
    with pytest.raises(TransportGTFSError, match="expanded size"):
        parse_gtfs_zip(raw)
    monkeypatch.setattr(transport_gtfs, "MAX_EXPANDED", 65536)
    corrupt = bytearray(raw)
    # Central-directory CRC is independent of decompressed data and must match.
    crc_at = corrupt.index(b"PK\x01\x02") + 16
    corrupt[crc_at] ^= 1
    with pytest.raises(TransportGTFSError):
        parse_gtfs_zip(corrupt)


@pytest.mark.parametrize("change", [
    {"stops.txt": "stop_id,stop_name\n001,One\n001,Duplicate\n"},
    {"stop_times.txt": "trip_id,stop_id,stop_sequence\nT1,001,1\nT1,002,1\n"},
    {"calendar_dates.txt": "service_id,date,exception_type\nWK,20261106,9\n"},
    {"shapes.txt": "shape_id,shape_pt_lat,shape_pt_lon,shape_pt_sequence\nS1,nan,0,1\n"},
])
def test_invalid_joins_are_declared_errors(change):
    with pytest.raises(TransportGTFSError):
        trip_itinerary(parse_gtfs_zip(zipped(TABLES | change)), "T1", "20261106")


def oracle_feed():
    feed = pb.FeedMessage()
    feed.header.gtfs_realtime_version = "2.0"
    feed.header.timestamp = 1793966400
    feed.header.incrementality = pb.FeedHeader.FULL_DATASET
    entity = feed.entity.add(id="vehicle-1")
    vehicle = entity.vehicle
    vehicle.trip.trip_id = "T1"
    vehicle.trip.route_id = "007"
    vehicle.vehicle.id = "bus001"
    vehicle.vehicle.license_plate = "B-01-CTF"
    vehicle.position.latitude = 44.4375
    vehicle.position.longitude = 26.125
    vehicle.position.bearing = 90
    vehicle.position.speed = 12.5
    vehicle.position.odometer = 123456.125
    vehicle.current_stop_sequence = 10
    vehicle.current_status = pb.VehiclePosition.STOPPED_AT
    vehicle.timestamp = 1793966400
    vehicle.stop_id = "001"
    carriage = vehicle.multi_carriage_details.add(id="C1", label="Front", occupancy_percentage=-1, carriage_sequence=1)
    carriage.occupancy_status = pb.VehiclePosition.NO_DATA_AVAILABLE
    update = feed.entity.add(id="trip-1").trip_update
    update.trip.trip_id = "T1"
    update.trip.start_time = "24:50:00"
    update.trip.start_date = "20261106"
    update.delay = -60
    update.timestamp = 1793966400
    stop = update.stop_time_update.add(stop_sequence=10, stop_id="001")
    stop.arrival.delay = -60
    stop.arrival.time = 1793966340
    stop.arrival.uncertainty = 0
    stop.departure.delay = 0
    stop.stop_time_properties.assigned_stop_id = "001"
    stop = update.stop_time_update.add(stop_sequence=20, stop_id="002")
    stop.schedule_relationship = pb.TripUpdate.StopTimeUpdate.SKIPPED
    alert = feed.entity.add(id="alert-1").alert
    alert.active_period.add(start=1793960000, end=1793990000)
    alert.informed_entity.add(route_id="007", stop_id="001")
    alert.header_text.translation.add(text="CSCTF{transit_alert}", language="en")
    alert.description_text.translation.add(text="Închis", language="ro")
    alert.cause = pb.Alert.CONSTRUCTION
    alert.effect = pb.Alert.DETOUR
    return feed


def test_official_protobuf_oracle_core_entities():
    """Official schema encoder is independent of the engine's handwritten reader."""
    feed = oracle_feed()
    result = decode_gtfs_rt(feed.SerializeToString(deterministic=True))
    assert result["header"] == {"gtfs_realtime_version": "2.0", "timestamp": 1793966400, "incrementality": 0}
    vehicle = result["entity"][0]["vehicle"]
    assert vehicle["position"] == {"latitude": 44.4375, "longitude": 26.125, "bearing": 90.0, "speed": 12.5, "odometer": 123456.125}
    assert vehicle["vehicle"]["license_plate"] == "B-01-CTF"
    assert vehicle["trip"]["route_id"] == "007"
    assert vehicle["multi_carriage_details"][0]["occupancy_percentage"] == -1
    update = result["entity"][1]["trip_update"]
    assert update["delay"] == -60
    assert update["stop_time_update"][0]["arrival"] == {"delay": -60, "time": 1793966340, "uncertainty": 0}
    assert update["stop_time_update"][0]["departure"] == {"delay": 0}
    assert update["stop_time_update"][1]["schedule_relationship"] == 1
    alert = result["entity"][2]["alert"]
    assert alert["header_text"]["translation"] == [{"text": "CSCTF{transit_alert}", "language": "en"}]
    assert alert["description_text"]["translation"][0]["text"] == "Închis"
    assert alert["active_period"][0] == {"start": 1793960000, "end": 1793990000}


def test_frozen_wire_and_unknown_extension():
    # Manually derived: field 1, length 5, header field 1, string "2.0".
    raw = bytes.fromhex("0a050a03322e30")
    assert decode_gtfs_rt(raw) == {"header": {"gtfs_realtime_version": "2.0"}}
    # Extension field 1000, length 3, ASCII xyz; no schema/library encoder used.
    result = decode_gtfs_rt(raw + bytes.fromhex("c23e0378797a"))
    assert result["_unknown"] == [{"field": 1000, "wire": 2, "value": "78797a"}]


@pytest.mark.parametrize("value", [-90.0, 0.0, 90.0])
def test_coordinate_boundaries(value):
    feed = oracle_feed()
    feed.entity[0].vehicle.position.latitude = value
    assert decode_gtfs_rt(feed.SerializeToString())["entity"][0]["vehicle"]["position"]["latitude"] == value


@pytest.mark.parametrize("value", [91.0, -91.0, math.nan, math.inf])
def test_bad_coordinates(value):
    feed = oracle_feed()
    feed.entity[0].vehicle.position.latitude = value
    with pytest.raises(TransportGTFSError):
        decode_gtfs_rt(feed.SerializeToString())


@pytest.mark.parametrize("raw", [b"", b"\x00", b"\xff" * 12, b"\x0a\xff\x7f", b"\x0a\x00", b"\x0b", b"\x0a\x03\x0a\x01\xff", bytes.fromhex("0a050a03322e300a050a03322e30")])
def test_bad_wire(raw):
    with pytest.raises(TransportGTFSError):
        decode_gtfs_rt(raw)


def test_missing_required_nested_and_duplicate_entity():
    feed = oracle_feed()
    feed.entity[0].vehicle.position.ClearField("longitude")
    with pytest.raises(TransportGTFSError):
        decode_gtfs_rt(feed.SerializePartialToString())
    feed = oracle_feed()
    feed.entity[1].id = feed.entity[0].id
    with pytest.raises(TransportGTFSError):
        decode_gtfs_rt(feed.SerializeToString())


def test_deterministic_mutations_never_leak_stdlib_errors():
    rng = random.Random(560)
    sample = oracle_feed().SerializeToString()
    candidates = [sample[:i] for i in range(len(sample))]
    candidates += [rng.randbytes(rng.randrange(100)) for _ in range(100)]
    for data in candidates:
        try:
            decode_gtfs_rt(data)
        except TransportGTFSError:
            pass
    for value in (None, {}, [], 123, "file.zip"):
        for parser in (decode_gtfs_rt, parse_gtfs_zip):
            with pytest.raises(TransportGTFSError):
                parser(value)


def test_cli_guard_and_files(tmp_path, capsys):
    assert main(["--help"]) == 0
    assert main([]) == 2
    assert main([str(tmp_path / "missing")]) == 2
    path = tmp_path / "feed.pb"
    path.write_bytes(oracle_feed().SerializeToString())
    assert main([str(path)]) == 0
    assert "transit_alert" in capsys.readouterr().out
    assert main([str(path), "--trip", "T1"]) == 2
    path = tmp_path / "feed.zip"
    path.write_bytes(zipped(TABLES))
    assert main([str(path), "--trip", "T1", "--date", "20261106"]) == 0
    assert '"active": false' in capsys.readouterr().out
