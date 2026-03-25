# blp_model.py

levels = {"U": 0, "C": 1, "S": 2, "TS": 3}


class Subject:
    def __init__(self, name, max_level, start_level):
        if levels[start_level] > levels[max_level]:
            raise ValueError("Start level cannot exceed max level")
        self.name = name
        self.max = max_level
        self.current = start_level


class Object:
    def __init__(self, name, level):
        self.name = name
        self.level = level


class BLPModel:
    def __init__(self):
        self.subjects = {}
        self.objects = {}

    # REQUIRED FUNCTIONS

    def add_subject(self, name, max_level, start_level):
        self.subjects[name] = Subject(name, max_level, start_level)

    def add_object(self, name, level):
        self.objects[name] = Object(name, level)

    def validate_levels(self, subject, obj):
        return subject.current == obj.level

    def set_level(self, name, new_level):
        subj = self.subjects[name]

        print(f"> Action: {name} SET LEVEL {new_level}...")

        if levels[new_level] > levels[subj.max]:
            print("> DENY: Above max clearance.")
            return

        if levels[new_level] < levels[subj.current]:
            print("> DENY: Cannot lower level.")
            return

        subj.current = new_level
        print(f"> INFO: Level set to {new_level}.")

    def read(self, name, obj_name):
        subj = self.subjects[name]
        obj = self.objects[obj_name]

        print(f"> Action: {name} READ {obj_name}...")

        # No Read Up
        if levels[obj.level] > levels[subj.max]:
            print(f"> DENY: Obj Lvl ({obj.level}) > Subj Max ({subj.max}).")
            return

        print(f"> ALLOW: Obj Lvl ({obj.level}) <= Subj Max ({subj.max}).")

        # Dynamic leveling
        if levels[obj.level] > levels[subj.current]:
            subj.current = obj.level
            print(f"> INFO: Raising {name}'s current level to {obj.level}.")

    def write(self, name, obj_name):
        subj = self.subjects[name]
        obj = self.objects[obj_name]

        print(f"> Action: {name} WRITE {obj_name}...")

        # No Write Down
        if levels[subj.current] > levels[obj.level]:
            print(f"> DENY: No Write Down (Subj {subj.current} > Obj {obj.level}).")
        else:
            print(f"> ALLOW: Subj Lvl ({subj.current}) <= Obj Lvl ({obj.level}).")

    def show_state(self):
        print("\n--- Current BLP State ---")
        for s in self.subjects.values():
            print(f"[Subject] {s.name}: Curr={s.current}, Max={s.max}")
        for o in self.objects.values():
            print(f"[Object]  {o.name}: Lvl={o.level}")
        print("--------------------------\n")