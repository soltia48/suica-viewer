import csv
from importlib.resources import files


class StationCodeLookup:
    """
    A class to lookup station information from station_codes.csv using line codes and station order codes.

    The CSV file should have the following columns:
    - 地区コード(16進): Area code (hex)
    - 線区コード(16進): Line code (hex)
    - 駅順コード(16進): Station order code (hex)
    - 会社名: Company name
    - 線区名: Line name
    - 駅名: Station name
    - 備考: Notes
    """

    def __init__(self):
        """
        Initialize the StationCodeLookup with data from CSV file.

        Args:
            csv_file_path: Path to the station codes CSV file
        """
        self.csv_file_path = files("suica_viewer").joinpath("station_codes.csv")
        self._stations_by_line_station: dict[str, dict[str, dict]] = {}
        self._stations_by_line: dict[str, list[dict]] = {}
        self._companies: set[str] = set()
        self._lines_by_company: dict[str, list[dict]] = {}

        self._load_data()

    def _normalize_hex_code(self, code: str | int) -> str:
        """
        Normalize hex code to uppercase string format.

        Args:
            code: Hex code as string or integer

        Returns:
            Normalized hex code as uppercase string
        """
        if isinstance(code, int):
            return f"{code:X}"
        elif isinstance(code, str):
            return code.upper().strip()
        else:
            raise ValueError(f"Invalid code type: {type(code)}")

    def _load_data(self) -> None:
        """Load station data from CSV file into internal data structures."""
        csv_path = self.csv_file_path

        if not csv_path.is_file():
            raise FileNotFoundError(
                f"Station codes CSV file not found: {self.csv_file_path}"
            )

        try:
            with csv_path.open("r", encoding="utf-8") as file:
                reader = csv.DictReader(file)

                for row in reader:
                    # Extract and normalize data
                    area_code = self._normalize_hex_code(row["地区コード(16進)"])
                    line_code = self._normalize_hex_code(row["線区コード(16進)"])
                    station_code = self._normalize_hex_code(row["駅順コード(16進)"])
                    company_name = row["会社名"].strip()
                    line_name = row["線区名"].strip()
                    station_name = row["駅名"].strip()
                    notes = row["備考"].strip()

                    # Create station info dictionary
                    station_info = {
                        "area_code": area_code,
                        "line_code": line_code,
                        "station_code": station_code,
                        "company_name": company_name,
                        "line_name": line_name,
                        "station_name": station_name,
                        "notes": notes,
                    }

                    # Index by line_code + station_code for fast lookup
                    if line_code not in self._stations_by_line_station:
                        self._stations_by_line_station[line_code] = {}
                    self._stations_by_line_station[line_code][
                        station_code
                    ] = station_info

                    # Index by line_code for line-based queries
                    if line_code not in self._stations_by_line:
                        self._stations_by_line[line_code] = []
                    self._stations_by_line[line_code].append(station_info)

                    # Track companies
                    self._companies.add(company_name)

                    # Index lines by company
                    if company_name not in self._lines_by_company:
                        self._lines_by_company[company_name] = []

                    # Add line info if not already present
                    line_info = {
                        "line_code": line_code,
                        "line_name": line_name,
                        "company_name": company_name,
                    }
                    if line_info not in self._lines_by_company[company_name]:
                        self._lines_by_company[company_name].append(line_info)

        except Exception as e:
            raise RuntimeError(
                f"Error loading station codes from {self.csv_file_path}: {e}"
            )

    def get_station_info(
        self, line_code: str | int, station_code: str | int
    ) -> dict | None:
        """
        Get station information by line code and station order code.

        Args:
            line_code: Line code (hex string or integer)
            station_code: Station order code (hex string or integer)

        Returns:
            Dictionary with station information or None if not found
        """
        try:
            normalized_line_code = self._normalize_hex_code(line_code)
            normalized_station_code = self._normalize_hex_code(station_code)

            return self._stations_by_line_station.get(normalized_line_code, {}).get(
                normalized_station_code
            )

        except ValueError as e:
            print(f"Error normalizing codes: {e}")
            return None

    def get_stations_by_line(self, line_code: str | int) -> list[dict]:
        """
        Get all stations for a specific line code.

        Args:
            line_code: Line code (hex string or integer)

        Returns:
            List of station information dictionaries
        """
        try:
            normalized_line_code = self._normalize_hex_code(line_code)
            return self._stations_by_line.get(normalized_line_code, [])

        except ValueError as e:
            print(f"Error normalizing line code: {e}")
            return []

    def get_all_companies(self) -> set[str]:
        """
        Get all company names in the dataset.

        Returns:
            Set of company names
        """
        return self._companies.copy()

    def get_lines_by_company(self, company_name: str) -> list[dict]:
        """
        Get all lines for a specific company.

        Args:
            company_name: Company name to search for

        Returns:
            List of line information dictionaries
        """
        return self._lines_by_company.get(company_name.strip(), [])

    def search_stations_by_name(self, station_name: str) -> list[dict]:
        """
        Search for stations by name (partial match).

        Args:
            station_name: Station name to search for

        Returns:
            List of matching station information dictionaries
        """
        results = []
        search_term = station_name.strip().lower()

        for line_stations in self._stations_by_line.values():
            for station in line_stations:
                if search_term in station["station_name"].lower():
                    results.append(station)

        return results

    def get_line_info(self, line_code: str | int) -> dict | None:
        """
        Get line information by line code.

        Args:
            line_code: Line code (hex string or integer)

        Returns:
            Dictionary with line information or None if not found
        """
        try:
            normalized_line_code = self._normalize_hex_code(line_code)
            stations = self._stations_by_line.get(normalized_line_code, [])

            if stations:
                # Return line info from the first station
                first_station = stations[0]
                return {
                    "line_code": first_station["line_code"],
                    "line_name": first_station["line_name"],
                    "company_name": first_station["company_name"],
                    "station_count": len(stations),
                }

            return None

        except ValueError as e:
            print(f"Error normalizing line code: {e}")
            return None

    def __len__(self) -> int:
        """Return the total number of stations."""
        return sum(len(stations) for stations in self._stations_by_line.values())

    def __repr__(self) -> str:
        """Return string representation of the lookup object."""
        return f"StationCodeLookup(stations={len(self)}, companies={len(self._companies)}, lines={len(self._stations_by_line)})"
